// src/api_register_owner.c
#include <kore/kore.h>
#include <kore/http.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h> // Для crypt()
#include <crypt.h>  // Для crypt()
#include "../includes/db.h"

// Упрощённая функция хеширования пароля (использует crypt)
char* hash_password_simple(const char* password) {
    // Используем статический сол для упрощения (ОЧЕНЬ ПЛОХО для продакшена!)
    // Лучше генерировать случайный сол каждый раз.
    const char* salt = "$1$salt123$"; // MD5-хеш с солью
    char* hashed = crypt(password, salt);
    if (hashed == NULL) {
        perror("crypt");
        return NULL;
    }
    // Возвращаем указатель на статическую строку из crypt.
    // !!! ВНИМАНИЕ: Это перезаписывается при следующем вызове crypt в том же потоке!
    // Для многопоточности или сохранения значения нужна копия.
    return hashed;
}


int api_register_owner(struct http_request *req) {
    // Шаг 1: Извлечение данных
    char *body_data;
    size_t body_len;
    struct json_tokener *tok;
    struct json_object *json_body, *jobj;
    const char *email, *password, *full_name, *company_name;
    char *hashed_password;
    int new_user_id = -1;
    int new_company_id = -1;
    int new_role_id = -1;
    int new_card_id = -1;

    printf("Received request to /api/auth/register-owner\n");

    // Проверяем метод
    if (req->method != HTTP_METHOD_POST) {
        http_response(req, 405, NULL, 0); // Method Not Allowed
        return (KORE_RESULT_OK);
    }

    // Извлекаем тело запроса
    http_populate_post(req);
    body_data = req->http_body->data;
    body_len = req->http_body->offset;

    if (!body_data) {
        printf("Request body is empty.\n");
        http_response(req, 400, "{\"status\": \"error\", \"reason\": \"empty_body\"}", 47);
        return (KORE_RESULT_OK);
    }

    // Парсим JSON
    tok = json_tokener_new();
    json_body = json_tokener_parse_ex(tok, body_data, body_len);
    json_tokener_free(tok);

    if (!json_body || !json_object_is_type(json_body, json_type_object)) {
        printf("Failed to parse JSON body.\n");
        http_response(req, 400, "{\"status\": \"error\", \"reason\": \"invalid_json\"}", 49);
        return (KORE_RESULT_OK);
    }

    // Получаем email, password, full_name, company_name из JSON
    if (!json_object_object_get_ex(json_body, "email", &jobj) ||
        !json_object_object_get_ex(json_body, "password", &jobj) ||
        !json_object_object_get_ex(json_body, "full_name", &jobj) ||
        !json_object_object_get_ex(json_body, "company_name", &jobj)) {
        printf("Missing required fields in JSON body.\n");
        json_object_put(json_body);
        http_response(req, 400, "{\"status\": \"error\", \"reason\": \"missing_required_fields\"}", 66);
        return (KORE_RESULT_OK);
    }
    email = json_object_get_string(jobj);
    jobj = NULL; json_object_object_get_ex(json_body, "password", &jobj); password = json_object_get_string(jobj);
    jobj = NULL; json_object_object_get_ex(json_body, "full_name", &jobj); full_name = json_object_get_string(jobj);
    jobj = NULL; json_object_object_get_ex(json_body, "company_name", &jobj); company_name = json_object_get_string(jobj);

    if (!email || !password || !full_name || !company_name) {
        printf("One of the required fields is NULL.\n");
        json_object_put(json_body);
        http_response(req, 400, "{\"status\": \"error\", \"reason\": \"null_field_value\"}", 60);
        return (KORE_RESULT_OK);
    }

    json_object_put(json_body); // Освобождаем память JSON

    // Шаг 2: Валидация (минимальная)
    if (strlen(email) == 0 || strlen(password) == 0 || strlen(full_name) == 0 || strlen(company_name) == 0) {
        printf("One of the required fields is empty.\n");
        http_response(req, 400, "{\"status\": \"error\", \"reason\": \"empty_field_value\"}", 62);
        return (KORE_RESULT_OK);
    }

    // Шаг 3: Хеширование пароля (упрощённо)
    hashed_password = hash_password_simple(password);
    if (!hashed_password) {
        printf("Failed to hash password.\n");
        http_response(req, 500, "{\"status\": \"error\", \"reason\": \"internal_error\"}", 52);
        return (KORE_RESULT_OK);
    }
    // !!! ВНИМАНИЕ: Значение hashed_password может быть перезаписано!
    // Создадим копию для безопасности в транзакции.
    char safe_hashed_password[256];
    snprintf(safe_hashed_password, sizeof(safe_hashed_password), "%s", hashed_password);


    // Шаг 4: Создание записей в БД (в одной транзакции для целостности)
    sqlite3_stmt *stmt;
    int rc;
    const char *sql_begin_transaction = "BEGIN TRANSACTION;";
    const char *sql_end_transaction = "COMMIT;";
    const char *sql_rollback_transaction = "ROLLBACK;";

    rc = sqlite3_exec(g_db_handle, sql_begin_transaction, 0, 0, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL begin transaction error: %s\n", sqlite3_errmsg(g_db_handle));
        http_response(req, 500, "{\"status\": \"error\", \"reason\": \"internal_error\"}", 52);
        return (KORE_RESULT_OK);
    }

    int transaction_failed = 0;

    // 4.1. Вставка в users
    const char *sql_insert_user = "INSERT INTO users (email, password_hash, full_name) VALUES (?, ?, ?);";
    rc = sqlite3_prepare_v2(g_db_handle, sql_insert_user, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error inserting user: %s\n", sqlite3_errmsg(g_db_handle));
        transaction_failed = 1;
    } else {
        sqlite3_bind_text(stmt, 1, email, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, safe_hashed_password, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, full_name, -1, SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "SQL step error inserting user: %s\n", sqlite3_errmsg(g_db_handle));
            transaction_failed = 1;
        } else {
            new_user_id = sqlite3_last_insert_rowid(g_db_handle); // Получаем ID нового пользователя
        }
        sqlite3_finalize(stmt);
    }

    if (!transaction_failed) {
        // 4.2. Вставка в companies
        const char *sql_insert_company = "INSERT INTO companies (name, created_by) VALUES (?, ?);";
        rc = sqlite3_prepare_v2(g_db_handle, sql_insert_company, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL prepare error inserting company: %s\n", sqlite3_errmsg(g_db_handle));
            transaction_failed = 1;
        } else {
            sqlite3_bind_text(stmt, 1, company_name, -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 2, new_user_id); // created_by = ID нового пользователя
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                fprintf(stderr, "SQL step error inserting company: %s\n", sqlite3_errmsg(g_db_handle));
                transaction_failed = 1;
            } else {
                new_company_id = sqlite3_last_insert_rowid(g_db_handle); // Получаем ID новой компании
            }
            sqlite3_finalize(stmt);
        }
    }

    if (!transaction_failed) {
        // 4.3. Вставка в user_company_roles
        const char *sql_insert_role = "INSERT INTO user_company_roles (user_id, company_id, role, status) VALUES (?, ?, 'owner', 'ACTIVE');";
        rc = sqlite3_prepare_v2(g_db_handle, sql_insert_role, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL prepare error inserting role: %s\n", sqlite3_errmsg(g_db_handle));
            transaction_failed = 1;
        } else {
            sqlite3_bind_int(stmt, 1, new_user_id);
            sqlite3_bind_int(stmt, 2, new_company_id);
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                fprintf(stderr, "SQL step error inserting role: %s\n", sqlite3_errmsg(g_db_handle));
                transaction_failed = 1;
            } else {
                 new_role_id = sqlite3_last_insert_rowid(g_db_handle); // Получаем ID новой роли
            }
            sqlite3_finalize(stmt);
        }
    }

    if (!transaction_failed) {
        // 4.4. Вставка в access_cards (упрощённо, без генерации реального TOTP-секрета)
        // !!! УПРОЩЕНИЕ: Создаём карту с фиксированным/тестовым TOTP-секретом.
        const char *dummy_totp_secret = "TESTSECRETTESTSEC"; // Используем для теста api_verify
        const char *sql_insert_card = "INSERT INTO access_cards (user_company_role_id, totp_secret, status) VALUES (?, ?, 'ACTIVE');";
        rc = sqlite3_prepare_v2(g_db_handle, sql_insert_card, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL prepare error inserting card: %s\n", sqlite3_errmsg(g_db_handle));
            transaction_failed = 1;
        } else {
            sqlite3_bind_int(stmt, 1, new_role_id); // user_company_role_id = ID новой роли
            sqlite3_bind_text(stmt, 2, dummy_totp_secret, -1, SQLITE_STATIC);
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                fprintf(stderr, "SQL step error inserting card: %s\n", sqlite3_errmsg(g_db_handle));
                transaction_failed = 1;
            } else {
                 new_card_id = sqlite3_last_insert_rowid(g_db_handle); // Получаем ID новой карты
            }
            sqlite3_finalize(stmt);
        }
    }

    // Завершаем транзакцию
    if (transaction_failed) {
        printf("Transaction failed, rolling back.\n");
        sqlite3_exec(g_db_handle, sql_rollback_transaction, 0, 0, 0);
        http_response(req, 500, "{\"status\": \"error\", \"reason\": \"registration_failed\"}", 57);
    } else {
        printf("Transaction successful. Created User(%d), Company(%d), Role(%d), Card(%d)\n", new_user_id, new_company_id, new_role_id, new_card_id);
        sqlite3_exec(g_db_handle, sql_end_transaction, 0, 0, 0);
        // Ответ об успехе (упрощённый)
        const char *success_message = "{\"status\": \"success\", \"message\": \"Owner and company created.\"}";
        http_response(req, 201, success_message, strlen(success_message)); // 201 Created
    }

    return (KORE_RESULT_OK);
}
