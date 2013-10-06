#include <errno.h>
#include <stdlib.h>
#include <cutils/str.h>

#include "cutest/CuTest.h"

#define LENGTH(x)    (sizeof(x)/sizeof(*x))

union str_test_str {
        struct {
                char *str;
                char *old;
                char *new;
                char *expected;
        };
        char *array[4];
};


void Test_str_replace(CuTest* tc) {

	unsigned int i;
	char *result;

	union str_test_str tests[] = {
		{ .array = { "he cried", "", "she", "he cried" }},
		{ .array = { "he cried", "he", "she", "she cried" }},
		{ .array = {"he cried", "he ", "she", "shecried" }},
		{ .array = {"he cried he cried", "he", "she", "she cried he cried" }},
	};

	for (i=0; i < LENGTH(tests); i++) {
		result = replace(tests[i].str, tests[i].old, tests[i].new);
		CuAssertStrEquals(tc, tests[i].expected, result);
		free(result);
	}
}


void Test_str_replace_errnos(CuTest* tc) {

	int rc;
	char *result;
	unsigned int i;
	unsigned int j;

	union str_test_str tests2[] = {
		{ .array = { "valid", "valid", NULL, "valid" }},
		{ .array = { "valid", NULL, NULL, "valid" }},
		{ .array = { NULL, NULL, NULL, "valid" }}
	};

	for (i=0; i < LENGTH(tests2); i++) {
		for (j=0; j < LENGTH(tests2[i].array) - 1; j++) {
			char *a = tests2[i].array[j % 3];
			char *b = tests2[i].array[(j + 1) % 3];
			char *c = tests2[i].array[(j + 2) % 3];

			result = replace(a, b, c);
			rc = errno;
			CuAssertPtrEquals(tc, result, NULL);
			CuAssertIntEquals(tc, rc, EINVAL);
		}
	}
}

void Test_str_replace_all(CuTest* tc) {

        unsigned int i;
        char *result;

        union str_test_str tests[] = {
                { .array = { "he cried", "", "she", "he cried" }},
                { .array = { "he cried", "he", "she", "she cried" }},
                { .array = { "he cried", "he ", "she", "shecried" }},
                { .array = { "he cried he cried", "he", "she", "she cried she cried" }},
        };

        for (i=0; i < LENGTH(tests); i++) {
                result = replace_all(tests[i].str, tests[i].old, tests[i].new);
                CuAssertStrEquals(tc, tests[i].expected, result);
                free(result);
        }
}

void Test_str_replace_all_errnos(CuTest* tc) {

	int rc;
	unsigned int i;
	unsigned int j;
	char *result;
        union str_test_str tests2[] = {
                { .array = { "valid", "valid", NULL, "valid" }},
                { .array = { "valid", NULL, NULL, "valid" }},
                { .array = { NULL, NULL, NULL, "valid" }}
        };

        for(i=0; i < LENGTH(tests2); i++) {
                for(j=0; j < LENGTH(tests2[i].array) - 1; j++) {
                        char *a = tests2[i].array[j % 3];
                        char *b = tests2[i].array[(j + 1) % 3];
                        char *c = tests2[i].array[(j + 2) % 3];

                        result = replace_all(a, b, c);
                        rc = errno;
                        CuAssertPtrEquals(tc, result, NULL);
                        CuAssertIntEquals(tc, rc, EINVAL);
        	}
	}
}

