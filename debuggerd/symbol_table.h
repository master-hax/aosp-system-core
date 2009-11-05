#ifndef SYMBOL_TABLE_H
#define SYMBOL_TABLE_H

typedef struct {
    unsigned int addr;
    unsigned int size;
    char *name;
} Symbol;

typedef struct {
    Symbol *symbols;
    int num_symbols;
} SymbolTable;

SymbolTable *symbol_table_create(const char *filename);
void symbol_table_free(SymbolTable *table);
const Symbol *symbol_table_lookup(SymbolTable *table, unsigned int addr);

#endif
