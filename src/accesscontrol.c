// src/main.c
#include <kore/kore.h> // Заголовки Kore
#include "../includes/db.h" // Заголовки нашей БД
#include <stdio.h>
#include <stdlib.h>

// Реализация глобальной переменной
sqlite3 *g_db_handle = NULL;

// Прототип функции инициализации БД (реализация будет в db.c)
// int init_db(sqlite3 *db); // Убираем, так как теперь в db.h

// Вызывается при запуске сервера
int kore_server_start(void) {
    const char *db_path = "access_control.db";

    printf("Opening database: %s\n", db_path);
    if (sqlite3_open(db_path, &g_db_handle) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(g_db_handle));
        sqlite3_close(g_db_handle);
        g_db_handle = NULL; // Убедимся, что указатель обнулен
        return (-1); // Ошибка при запуске сервера
    }

    printf("Database opened successfully.\n");

    // Инициализируем таблицы
    if (init_db(g_db_handle) != SQLITE_OK) {
        fprintf(stderr, "Failed to initialize database schema.\n");
        sqlite3_close(g_db_handle);
        g_db_handle = NULL;
        return (-1); // Ошибка при запуске сервера
    }
    printf("Database schema initialized successfully.\n");

    // Kore вызовет другие инициализации и начнет принимать соединения
    return (KORE_RESULT_OK);
}

// Вызывается при остановке сервера
void kore_server_stop(void) {
    if (g_db_handle != NULL) {
        printf("Closing database connection.\n");
        sqlite3_close(g_db_handle);
        g_db_handle = NULL;
    }
}
