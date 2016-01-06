%define parse.error verbose

%{
#include <stdio.h>

#include "fs-ast.h"
#include "fs-parse.h"
#include "fs-lex.h"

extern int lineno;

void yyerror(struct fs_node **node, yyscan_t scanner, const char *s)
{
	fprintf(stderr, "error(%d): %s\n", lineno, s);
}

%}

%union {
	struct fs_node *node;
	char *string;
	unsigned int integer;
}
%code requires {

#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif

}
 
%define api.pure
%lex-param   { yyscan_t scanner }
%parse-param { struct fs_node **script }
%parse-param { yyscan_t scanner }

%token RETURN
%token <string> PSPEC IDENT STRING OP AOP
%token <integer> INT

%type <node> script probes probe stmts stmt
%type <node> block expr variable call vargs

%left OP
%precedence '!'

%start script

%%

script : probes
		{ *script = fs_script_new($1); }
;

probes : probe
		{ $$ = $1; }
       | probes probe
		{ insque_tail($2, $1); }
;

probe : PSPEC block
		{ $$ = fs_probe_new($1, NULL, $2); }
      | PSPEC '/' expr '/' block
		{ $$ = fs_probe_new($1, $3, $5); }
;

/* pred : expr */
/* 		{ $$ = fs_pred_new($1, strdup("!="), fs_int_new(0)); } */
/*      | expr CMP expr */
/* 		{ $$ = fs_pred_new($1, $2, $3); } */
/* ; */

stmts : stmt
		{ $$ = $1; }
      | stmts ';' stmt
		{ insque_tail($3, $1); }
;

stmt : variable AOP expr
		{ $$ = fs_assign_new($1, $2, $3); }
     /* | variable AGG call */
     /* 		{ $$ = fs_agg_new($1, $3); } */
     | expr
		{ $$ = $1; }
     | RETURN expr
		{ $$ = fs_return_new($2); }
;

block : '{' stmts '}'
		{ $$ = $2; }
      | '{' stmts ';' '}'
		{ $$ = $2; }
;

expr : INT
		{ $$ = fs_int_new($1); }
     | STRING
		{ $$ = fs_str_new($1); }
     | expr OP expr
     		{ $$ = fs_binop_new($1, $2, $3); }
     | '!' expr
		{ $$ = fs_not_new($2); }
     | '(' expr ')'
		{ $$ = $2; }
     | variable
		{ $$ = $1; }
     | call
		{ $$ = $1; }
;

variable :/*  IDENT */
	 /* 	{ $$ = fs_var_new($1); } */
         /* | */ IDENT '[' vargs ']'
		{ $$ = fs_map_new($1, $3); }
;

call: IDENT '(' ')'
		{ $$ = fs_call_new($1, NULL); }
    | IDENT '(' vargs ')'
		{ $$ = fs_call_new($1, $3); }
;

vargs : expr
		{ $$ = $1; }
      | vargs ',' expr
		{ insque_tail($3, $1); }
;

%%

