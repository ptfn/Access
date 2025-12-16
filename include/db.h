// includes/db.h
#ifndef DB_H
#define DB_H

#include <sqlite3.h> // Подключаем sqlite3.h здесь, чтобы другие файлы могли его использовать через этот заголовок

// Глобальная переменная для хранения дескриптора БД
extern sqlite3 *g_db_handle;

// Прототипы функций инициализации БД
int init_db(sqlite3 *db);
int ensure_connection(); // Проверяет, подключена ли БД

#endif /* DB_H */
