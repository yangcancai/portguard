#ifndef TELEGRAM_NOTIFY_H
#define TELEGRAM_NOTIFY_H

#define PORTGUARD_TG_TOKEN_MAX_LEN 192
#define PORTGUARD_TG_CHAT_ID_MAX_LEN 128

int telegram_bot_token_is_valid(const char *token);
int telegram_chat_id_is_valid(const char *chat_id);
int telegram_configure_console(fko_srv_options_t *opts);
void telegram_notify_access(const fko_srv_options_t *opts,
        const spa_data_t *spadat, time_t opened_at, time_t expires_at);

#endif /* TELEGRAM_NOTIFY_H */
