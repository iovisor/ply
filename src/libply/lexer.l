/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

%option reentrant noyywrap never-interactive nounistd
%option bison-locations

%{

/* ignore harmless bug in old versions of flex */
#pragma GCC diagnostic ignored "-Wsign-compare"


#include <stdio.h>

#include "grammar.h"

static void loc_update(struct nloc *loc, const char *token) {
	loc->first_line = loc->last_line;
	loc->first_column = loc->last_column;

	for (; *token; token++) {
		if (*token == '\n') {
			loc->last_line++;
			loc->last_column = 0;
			continue;
		}

		loc->last_column++;
	}
}

#define YY_USER_ACTION loc_update(yylloc, yytext);

%}

uaz		[_a-zA-Z]
uazd		[_a-zA-Z0-9]

ident		{uaz}{uazd}*
agg		@{uazd}*
env		${uazd}+
pspec		{ident}:[^ \n\r\t]*

%x COMMENT
%%

"/"[ \n\r\t]*"{"	{ return ENDPRED; }
"if"			{ return IF;      }
"else"			{ return ELSE;    }
"return"		{ return RETURN;  }
"delete"		{ return DELETE;  }
"&&"			{ return AND;     }
"^^"			{ return XOR;     }
"||"			{ return OR;      }
"<<"			{ return LSH;     }
">>"			{ return RSH;     }
"<="			{ return LE;      }
">="			{ return GE;      }
"=="			{ return EQ;      }
"!="			{ return NE;      }
"->"			{ return DEREF;   }

"BEGIN"			{ *yylval = node_string(yylloc, strdup(yytext));       return PSPEC;  }
"END"			{ *yylval = node_string(yylloc, strdup(yytext));       return PSPEC;  }

\"[^\0\"]*\"		{ *yylval = node_string(yylloc, strdup(yytext));       return STRING; }
[_0-9]+			{ *yylval = node_num   (yylloc, strdup(yytext));       return NUMBER; }
0b[_01]+		{ *yylval = node_num   (yylloc, strdup(yytext));       return NUMBER; }
0[xX][_0-9a-fA-F]+	{ *yylval = node_num   (yylloc, strdup(yytext));       return NUMBER; }
{ident}			{ *yylval = node_expr  (yylloc, strdup(yytext), NULL); return IDENT;  }
{agg}			{ *yylval = node_expr_ident(yylloc, strdup(yytext));   return AGG;    }
{env}			{ *yylval = node_expr_ident(yylloc, strdup(yytext));   return IDENT;  }
{pspec}			{ *yylval = node_string(yylloc, strdup(yytext));       return PSPEC;  }

#.*\n			;
"/*"			BEGIN(COMMENT);
<COMMENT>"*/"		BEGIN(INITIAL);
<COMMENT>.		;

[=@$.,;+\-*/%<>&~\^|!()\[\]{}]	{ return *yytext; }

[ \n\r\t]		;

. { fprintf(stderr, "%d: error: unknown token\n", yylloc->first_line); yyterminate(); }

%%
