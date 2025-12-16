// src/api_verify.c
#include <kore/kore.h>
#include <kore/http.h>
#include <sqlite3.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "../includes/db.h"

// Прототип функции для проверки TOTP
// Для упрощения, используем oathtool или liboath.
// Предположим, есть функция check_totp(const char *secret, long timestamp, const char *input_code)
// Пока создадим заглушку, которая проверяет код на равенство фиксированному значению.
int check_totp_simple(const char *expected_current_code, const char *input_code) {
    // Сравниваем коды (должны быть 6-значными строками)
    if (strlen(expected_current_code) != 6 || strlen(input_code) != 6) {
        return 0; // Неверная длина
    }
    return (strncmp(expected_current_code, input_code, 6) == 0) ? 1 : 0;
}


// Обработчик эндпоинта /api/access/verify
int api_verify(struct http_request *req) {
    // Шаг 1: Извлечение данных
    const char *api_key_header;
    char *body_data;
    size_t body_len;
    struct json_tokener *tok;
    struct json_object *json_body, *jobj;
    const char *company_id_str, *code_str;
    int company_id, gate_id, user_id, card_id;
    char totp_secret[33]; // Достаточно для base32 строки 160 бит (20 байт) = 32 символа + 1 для \0
    char user_name[256];
    int found_match = 0;

    printf("Received request to /api/access/verify\n");

    // Проверяем метод
    if (req->method != HTTP_METHOD_POST) {
        http_response(req, 405, NULL, 0); // Method Not Allowed
        return (KORE_RESULT_OK);
    }

    // Извлекаем X-API-Key
    api_key_header = http_request_header(req, "X-API-Key");
    if (!api_key_header) {
        // В реальности храните и сверяйте хеш!
        printf("X-API-Key header missing.\n");
        http_response(req, 401, "{\"status\": \"denied\", \"reason\": \"missing_api_key\"}", 54);
        return (KORE_RESULT_OK);
    }

    // Извлекаем тело запроса
    http_populate_post(req);
    body_data = req->http_body->data;
    body_len = req->http_body->offset;

    if (!body_data) {
        printf("Request body is empty.\n");
        http_response(req, 400, "{\"status\": \"denied\", \"reason\": \"empty_body\"}", 48);
        return (KORE_RESULT_OK);
    }

    // Парсим JSON
    tok = json_tokener_new();
    json_body = json_tokener_parse_ex(tok, body_data, body_len);
    json_tokener_free(tok);

    if (!json_body || !json_object_is_type(json_body, json_type_object)) {
        printf("Failed to parse JSON body.\n");
        http_response(req, 400, "{\"status\": \"denied\", \"reason\": \"invalid_json\"}", 50);
        return (KORE_RESULT_OK);
    }

    // Получаем company_id и code из JSON
    if (!json_object_object_get_ex(json_body, "company_id", &jobj)) {
        printf("Missing 'company_id' in JSON body.\n");
        json_object_put(json_body);
        http_response(req, 400, "{\"status\": \"denied\", \"reason\": \"missing_company_id\"}", 58);
        return (KORE_RESULT_OK);
    }
    company_id_str = json_object_get_string(jobj);
    if (!company_id_str || sscanf(company_id_str, "%d", &company_id) != 1) { // Преобразуем строку UUID в int (упрощение)
         printf("Invalid 'company_id' format in JSON body (expected integer for simplicity).\n");
        json_object_put(json_body);
        http_response(req, 400, "{\"status\": \"denied\", \"reason\": \"invalid_company_id_format\"}", 70);
        return (KORE_RESULT_OK);
    }

    if (!json_object_object_get_ex(json_body, "code", &jobj)) {
        printf("Missing 'code' in JSON body.\n");
        json_object_put(json_body);
        http_response(req, 400, "{\"status\": \"denied\", \"reason\": \"missing_code\"}", 50);
        return (KORE_RESULT_OK);
    }
    code_str = json_object_get_string(jobj);
    if (!code_str || strlen(code_str) != 6) { // Проверяем длину кода
         printf("Invalid 'code' format in JSON body (expected 6 digits string).\n");
        json_object_put(json_body);
        http_response(req, 400, "{\"status\": \"denied\", \"reason\": \"invalid_code_format\"}", 60);
        return (KORE_RESULT_OK);
    }

    json_object_put(json_body); // Освобождаем память JSON

    // Шаг 2: Проверка API-ключа
    sqlite3_stmt *stmt;
    const char *sql_check_gate = "SELECT id FROM gates WHERE api_key_hash = ? AND company_id = ? AND is_active = 1;";
    int rc = sqlite3_prepare_v2(g_db_handle, sql_check_gate, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error checking gate: %s\n", sqlite3_errmsg(g_db_handle));
        http_response(req, 500, "{\"status\": \"error\", \"reason\": \"internal_error\"}", 52);
        return (KORE_RESULT_OK);
    }

    sqlite3_bind_text(stmt, 1, api_key_header, -1, SQLITE_STATIC); // Упрощение: plain text
    sqlite3_bind_int(stmt, 2, company_id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        // Турникет не найден или неактивен или не принадлежит компании
        printf("Invalid or inactive API key for company %d.\n", company_id);
        sqlite3_finalize(stmt);
        http_response(req, 401, "{\"status\": \"denied\", \"reason\": \"invalid_api_key\"}", 54);
        return (KORE_RESULT_OK);
    }
    gate_id = sqlite3_column_int(stmt, 0); // Получаем ID турникета
    sqlite3_finalize(stmt);

    // Шаг 3: Проверка кода (упрощённая логика TOTP)
    // Запрашиваем все активные totp_secret для сотрудников в компании

    const char *sql_find_secrets = "SELECT ac.id, ucr.user_id, u.full_name, ac.totp_secret " // Выбираем id карты, id юзера, имя, секрет
                                   "FROM access_cards ac "
                                   "JOIN user_company_roles ucr ON ac.user_company_role_id = ucr.id "
                                   "JOIN users u ON ucr.user_id = u.id "
                                   "WHERE ucr.company_id = ? AND ucr.status = 'ACTIVE' AND ac.status = 'ACTIVE';";

    rc = sqlite3_prepare_v2(g_db_handle, sql_find_secrets, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL prepare error finding secrets: %s\n", sqlite3_errmsg(g_db_handle));
        http_response(req, 500, "{\"status\": \"error\", \"reason\": \"internal_error\"}", 52);
        return (KORE_RESULT_OK);
    }

    sqlite3_bind_int(stmt, 1, company_id);

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && !found_match) {
         card_id = sqlite3_column_int(stmt, 0);
         user_id = sqlite3_column_int(stmt, 1);
         const char *db_full_name = (const char*)sqlite3_column_text(stmt, 2);
         const char *db_totp_secret = (const char*)sqlite3_column_text(stmt, 3);

         snprintf(user_name, sizeof(user_name), "%s", db_full_name ? db_full_name : "Unknown User");

         if (strcmp(db_totp_secret, "TESTSECRETTESTSEC") == 0) {
             if (check_totp_simple("987654", code_str)) { // Подставляем фиксированный "ожидаемый" код
                 found_match = 1;
             }
         }
    }

    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL step error during iteration: %s\n", sqlite3_errmsg(g_db_handle));
        http_response(req, 500, "{\"status\": \"error\", \"reason\": \"internal_error\"}", 52);
        return (KORE_RESULT_OK);
    }

    // Шаг 4: Фиксация результата и ответ
    const char *response_granted = "{\"status\": \"granted\", \"user_name\": \"%s\"}";
    const char *response_denied = "{\"status\": \"denied\", \"reason\": \"invalid_code\"}";
    char response_body[256];

    const char *sql_insert_history = "INSERT INTO access_history (access_card_id, user_id, company_id, gate_id, status, reason, used_code) VALUES (?, ?, ?, ?, ?, ?, ?);";
    sqlite3_prepare_v2(g_db_handle, sql_insert_history, -1, &stmt, NULL); // Игнорируем ошибку подготовки для упрощения
    sqlite3_bind_int(stmt, 1, found_match ? card_id : 0); // 0 если не найдено
    sqlite3_bind_int(stmt, 2, found_match ? user_id : 0); // 0 если не найдено
    sqlite3_bind_int(stmt, 3, company_id);
    sqlite3_bind_int(stmt, 4, gate_id);
    sqlite3_bind_text(stmt, 5, found_match ? "GRANTED" : "DENIED", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, found_match ? "success" : "invalid_code", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, code_str, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (found_match) {
        printf("Access granted for user %s (card_id=%d) at gate %d.\n", user_name, card_id, gate_id);
        snprintf(response_body, sizeof(response_body), response_granted, user_name);
        http_response(req, 200, response_body, strlen(response_body));
    } else {
        printf("Access denied for code %s at gate %d for company %d.\n", code_str, gate_id, company_id);
        http_response(req, 200, response_denied, strlen(response_denied)); // Статус 200, но {"status": "denied"}
    }

    return (KORE_RESULT_OK);
}
