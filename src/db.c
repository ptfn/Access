// src/db.c
#include "../include/db.h"
#include <stdio.h>
#include <string.h>

// Реализация функции инициализации таблиц
int init_db(sqlite3 *db) {
    if (!db) {
         fprintf(stderr, "Database handle is NULL in init_db.\n");
         return SQLITE_ERROR; // Или SQLITE_MISUSE
    }

    char *sql_create_users =
        "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "email TEXT UNIQUE NOT NULL, "
            "password_hash TEXT NOT NULL, "
            "full_name TEXT NOT NULL"
        ");";

    char *sql_create_companies =
        "CREATE TABLE IF NOT EXISTS companies ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "name TEXT NOT NULL, "
            "created_by INTEGER, "
            "FOREIGN KEY(created_by) REFERENCES users(id)"
        ");";

    char *sql_create_user_company_roles =
        "CREATE TABLE IF NOT EXISTS user_company_roles ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "user_id INTEGER NOT NULL, "
            "company_id INTEGER NOT NULL, "
            "role TEXT DEFAULT 'employee', " // 'owner', 'admin', 'employee'
            "status TEXT DEFAULT 'ACTIVE', " // 'INVITED', 'ACTIVE', 'BLOCKED'
            "UNIQUE(user_id, company_id), "
            "FOREIGN KEY(user_id) REFERENCES users(id), "
            "FOREIGN KEY(company_id) REFERENCES companies(id)"
        ");";

    char *sql_create_access_cards =
        "CREATE TABLE IF NOT EXISTS access_cards ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "user_company_role_id INTEGER NOT NULL, "
            "totp_secret TEXT NOT NULL, " // Упрощение: хранится как есть
            "status TEXT DEFAULT 'ACTIVE', " // 'ACTIVE', 'SUSPENDED', 'LOST'
            "issued_at DATETIME DEFAULT CURRENT_TIMESTAMP, "
            "last_used_at DATETIME NULL, "
            "FOREIGN KEY(user_company_role_id) REFERENCES user_company_roles(id)"
        ");";

    char *sql_create_gates =
        "CREATE TABLE IF NOT EXISTS gates ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "company_id INTEGER NOT NULL, "
            "api_key_hash TEXT NOT NULL, " // Упрощение: хранится как есть или plain text hash
            "name TEXT, "
            "is_active BOOLEAN DEFAULT 1, "
            "FOREIGN KEY(company_id) REFERENCES companies(id)"
        ");";

    char *sql_create_access_history =
        "CREATE TABLE IF NOT EXISTS access_history ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "access_card_id INTEGER NOT NULL, "
            "user_id INTEGER NOT NULL, "
            "company_id INTEGER NOT NULL, "
            "gate_id INTEGER, " // Может быть NULL для систем без ID турникета
            "attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP, "
            "status TEXT NOT NULL, " // 'GRANTED', 'DENIED'
            "reason TEXT, "         // 'success', 'invalid_code', etc.
            "used_code TEXT, "       // Упрощение: хранить введенный код (НЕ безопасно!)
            "FOREIGN KEY(access_card_id) REFERENCES access_cards(id), "
            "FOREIGN KEY(user_id) REFERENCES users(id), "
            "FOREIGN KEY(company_id) REFERENCES companies(id), "
            "FOREIGN KEY(gate_id) REFERENCES gates(id)"
        ");";


    // Выполняем SQL-запросы для создания таблиц
    char *err_msg = 0;
    int rc;

    rc = sqlite3_exec(db, sql_create_users, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating users table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return rc;
    }

    rc = sqlite3_exec(db, sql_create_companies, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating companies table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return rc;
    }

     rc = sqlite3_exec(db, sql_create_user_company_roles, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating user_company_roles table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return rc;
    }

     rc = sqlite3_exec(db, sql_create_access_cards, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating access_cards table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return rc;
    }

     rc = sqlite3_exec(db, sql_create_gates, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating gates table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return rc;
    }

     rc = sqlite3_exec(db, sql_create_access_history, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error creating access_history table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return rc;
    }

    printf("All tables checked/created successfully.\n");
    return SQLITE_OK;
}

// Простая функция для проверки подключения
int ensure_connection() {
    if (g_db_handle == NULL) {
        fprintf(stderr, "Database connection is not established!\n");
        return KORE_RESULT_ERROR;
    }
    return KORE_RESULT_OK;
}
