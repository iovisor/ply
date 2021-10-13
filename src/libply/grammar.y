/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

/* Don't allow any ambiguity in the grammar */
%expect 0

%defines
%locations
%define api.pure
%define parse.error verbose

%lex-param   { void *scanner }
%parse-param { void *scanner }
%parse-param { struct ply *ply }

%code requires {
#include <ply/node.h>

#define YYLTYPE struct nloc

struct ply;
} 

%{
#include <stdio.h>
#include <stdint.h>

#include "grammar.h"
#include "lexer.h"

void yyerror(struct nloc *loc, yyscan_t scanner, struct ply *ply, const char *s)
{
	fprintf(stderr, "%d: error: %s\n", loc->first_line, s);
}

extern int __ply_probe_alloc(struct ply *ply, struct node *pspec, struct node *ast);

%}

%initial-action {
	@$.last_line = 1;
};

%define api.value.type { struct node * }

%token ENDPRED IF ELSE RETURN DELETE EQ NE LE GE LSH RSH AND XOR OR DEREF PSPEC IDENT AGG STRING NUMBER

/* C if-else associativity */
%right ')' ELSE

%start probes

%%

probes
: probe
| probe probes
;

probe
: PSPEC stmt      { __ply_probe_alloc(ply, $1, $2); }
| PSPEC predicate { __ply_probe_alloc(ply, $1, $2); }
;

/* Support dtrace-style predicates as well as normal if guards. I.e.
 * `provider:probe if (pid == 42) @ = count();` is equivalent to
 * `provider:probe / pid == 42 / { @ = count(); }`. */
predicate
: '/' expr ENDPRED stmts '}' {
	$$ = node_expr(&@$, "if", $2, node_expr(&@$, "{}", $4, NULL), NULL);
 }

stmts
: stmt
| stmt stmts { $$ = node_append($1, $2); }
;

stmt
: block
| branch
| jump
| delete
| expr_stmt
| assign
| aggregate
;

block
: '{' '}'	{ $$ = node_expr(&@$, "{}", NULL); }
| '{' stmts '}' { $$ = node_expr(&@$, "{}", $2, NULL); }
;

branch
: IF '(' expr ')' stmt			{ $$ = node_expr(&@$, "if", $3, $5, NULL); }
| IF '(' expr ')' stmt ELSE stmt	{ $$ = node_expr(&@$, "if", $3, $5, $7, NULL); }
;

jump
: RETURN ';' { $$ = node_expr(&@$, "return", NULL); }
;

delete
: DELETE map ';' { $$ = node_expr(&@$, "delete", $2, NULL); }
;

expr_stmt
: expr ';'
;

assign
: map '=' expr ';' { $$ = node_expr(&@$, "=", $1, $3, NULL); }
;

aggregate
: aggregation '=' expr ';' { $$ = node_expr(&@$, "@=", $1, $3, NULL); }
;

opt_exprs
: exprs
| %empty { $$ = NULL; }
;


exprs
: expr
| expr ',' exprs { $$ = node_append($1, $3); }
;

expr
: logor
;

logor
: logxor
| logor OR logxor { $$ = node_expr(&@$, "||", $1, $3, NULL); }
;

logxor
: logand
| logxor XOR logand { $$ = node_expr(&@$, "^^", $1, $3, NULL); }
;

logand
: or
| logand AND or { $$ = node_expr(&@$, "&&", $1, $3, NULL); }
;

or
: xor
| or '|' xor { $$ = node_expr(&@$, "|", $1, $3, NULL); }
;

xor
: and
| xor '^' and { $$ = node_expr(&@$, "^", $1, $3, NULL); }
;

and
: eq
| and '&' eq { $$ = node_expr(&@$, "&", $1, $3, NULL); }
;

eq
: rel
| eq EQ rel { $$ = node_expr(&@$, "==", $1, $3, NULL); }
| eq NE rel { $$ = node_expr(&@$, "!=", $1, $3, NULL); }
;

rel
: shift
| rel '<' shift { $$ = node_expr(&@$,  "<", $1, $3, NULL); }
| rel '>' shift { $$ = node_expr(&@$,  ">", $1, $3, NULL); }
| rel LE  shift { $$ = node_expr(&@$, "<=", $1, $3, NULL); }
| rel GE  shift { $$ = node_expr(&@$, ">=", $1, $3, NULL); }
;

shift
: term
| shift LSH term { $$ = node_expr(&@$, "<<", $1, $3, NULL); }
| shift RSH term { $$ = node_expr(&@$, ">>", $1, $3, NULL); }
;

term
: fact
| term '+' fact { $$ = node_expr(&@$, "+", $1, $3, NULL); }
| term '-' fact { $$ = node_expr(&@$, "-", $1, $3, NULL); }
;

fact
: unary
| fact '*' unary { $$ = node_expr(&@$, "*", $1, $3, NULL); }
| fact '/' unary { $$ = node_expr(&@$, "/", $1, $3, NULL); }
| fact '%' unary { $$ = node_expr(&@$, "%", $1, $3, NULL); }
;

unary
: basic
| func
| map
| basic '.'   IDENT { $$ = node_expr(&@$,  ".", $1, node_string(&@3, $3->expr.func), NULL); }
| basic DEREF IDENT { $$ = node_expr(&@$, "->", $1, node_string(&@3, $3->expr.func), NULL); }
/* | '&' unary { $$ = node_expr(&@$, "u&", $2, NULL); } */
| '*' unary { $$ = node_expr(&@$, "u*", $2, NULL); }
| '-' unary { $$ = node_expr(&@$, "u-", $2, NULL); }
| '~' unary { $$ = node_expr(&@$, "u~", $2, NULL); }
| '!' unary { $$ = node_expr(&@$, "u!", $2, NULL); }
;

basic
: NUMBER
| STRING
| IDENT
| AGG
| '(' expr ')'	{ $$ = $2; }
;

func
: IDENT '(' opt_exprs ')' { $$ = $3 ? node_expr_append(&@$, $1, $3) : $1; }
;

map
: IDENT key { $$ = node_expr(&@$, "[]", $1, $2, NULL); }
;

aggregation
: AGG key { $$ = node_expr(&@$, "[]", $1, $2, NULL); }
;

key
: '[' exprs ']' { $$ = node_expr(&@$, ":struct", $2, NULL); }
;

%%

