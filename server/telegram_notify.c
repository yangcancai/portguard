/**
 * \file server/telegram_notify.c
 *
 * \brief PortGuard Telegram notifications and console configuration.
 */

#include "fwknopd_common.h"
#include "telegram_notify.h"
#include "log_msg.h"

#include <fcntl.h>
#include <termios.h>
#include <sys/wait.h>

#define TG_MESSAGE_MAX_LEN 1600
#define TG_ENCODED_MAX_LEN 5000
#define TG_CURL_CONFIG_MAX_LEN 7000

static time_t last_notification_at = 0;

static int
write_all(const int fd, const char *buf, const size_t len)
{
    size_t written = 0;

    while(written < len)
    {
        ssize_t rv = write(fd, buf + written, len - written);
        if(rv < 0 && errno == EINTR)
            continue;
        if(rv <= 0)
            return 0;
        written += (size_t)rv;
    }
    return 1;
}

static int
url_encode(const char *input, char *output, const size_t output_size)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t in_pos, out_pos = 0;

    if(input == NULL || output == NULL || output_size == 0)
        return 0;

    for(in_pos = 0; input[in_pos] != '\0'; in_pos++)
    {
        unsigned char ch = (unsigned char)input[in_pos];
        if(isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~')
        {
            if(out_pos + 1 >= output_size)
                return 0;
            output[out_pos++] = (char)ch;
        }
        else
        {
            if(out_pos + 3 >= output_size)
                return 0;
            output[out_pos++] = '%';
            output[out_pos++] = hex[ch >> 4];
            output[out_pos++] = hex[ch & 0x0f];
        }
    }
    output[out_pos] = '\0';
    return 1;
}

int
telegram_bot_token_is_valid(const char *token)
{
    const char *colon;
    size_t i, len;

    if(token == NULL)
        return 0;
    len = strlen(token);
    if(len < 3 || len >= PORTGUARD_TG_TOKEN_MAX_LEN)
        return 0;

    colon = strchr(token, ':');
    if(colon == NULL || colon == token || colon[1] == '\0'
            || strchr(colon + 1, ':') != NULL)
        return 0;

    for(i = 0; token + i < colon; i++)
        if(!isdigit((unsigned char)token[i]))
            return 0;
    for(i = (size_t)(colon - token) + 1; i < len; i++)
        if(!isalnum((unsigned char)token[i]) && token[i] != '_'
                && token[i] != '-')
            return 0;
    return 1;
}

int
telegram_chat_id_is_valid(const char *chat_id)
{
    size_t i = 0, len;

    if(chat_id == NULL)
        return 0;
    len = strlen(chat_id);
    if(len == 0 || len >= PORTGUARD_TG_CHAT_ID_MAX_LEN)
        return 0;

    if(chat_id[0] == '@')
    {
        if(len < 2)
            return 0;
        for(i = 1; i < len; i++)
            if(!isalnum((unsigned char)chat_id[i]) && chat_id[i] != '_')
                return 0;
        return 1;
    }

    if(chat_id[0] == '-')
        i = 1;
    if(i == len)
        return 0;
    for(; i < len; i++)
        if(!isdigit((unsigned char)chat_id[i]))
            return 0;
    return 1;
}

static int
run_curl_config(const char *curl_config)
{
    int pipe_fd[2], status = 0, write_ok;
    pid_t pid;
    struct sigaction ignore_action, old_action;
    sigset_t block_mask, old_mask;

    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGCHLD);
    if(sigprocmask(SIG_BLOCK, &block_mask, &old_mask) != 0)
        return 0;
    if(pipe(pipe_fd) != 0)
    {
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        return 0;
    }

    pid = fork();
    if(pid == 0)
    {
        signal(SIGCHLD, SIG_DFL);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        close(pipe_fd[1]);
        if(dup2(pipe_fd[0], STDIN_FILENO) < 0)
            _exit(126);
        close(pipe_fd[0]);
        execlp("curl", "curl", "--config", "-", (char *)NULL);
        _exit(127);
    }
    if(pid < 0)
    {
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        sigprocmask(SIG_SETMASK, &old_mask, NULL);
        return 0;
    }

    close(pipe_fd[0]);
    memset(&ignore_action, 0, sizeof(ignore_action));
    ignore_action.sa_handler = SIG_IGN;
    sigemptyset(&ignore_action.sa_mask);
    sigaction(SIGPIPE, &ignore_action, &old_action);
    write_ok = write_all(pipe_fd[1], curl_config, strlen(curl_config));
    close(pipe_fd[1]);
    sigaction(SIGPIPE, &old_action, NULL);

    while(waitpid(pid, &status, 0) < 0)
    {
        if(errno != EINTR)
        {
            sigprocmask(SIG_SETMASK, &old_mask, NULL);
            return 0;
        }
    }
    sigprocmask(SIG_SETMASK, &old_mask, NULL);
    return write_ok && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int
send_message(const char *token, const char *chat_id, const char *message)
{
    char encoded_chat[TG_ENCODED_MAX_LEN] = {0};
    char encoded_message[TG_ENCODED_MAX_LEN] = {0};
    char curl_config[TG_CURL_CONFIG_MAX_LEN] = {0};
    int rv;

    if(!telegram_bot_token_is_valid(token)
            || !telegram_chat_id_is_valid(chat_id)
            || !url_encode(chat_id, encoded_chat, sizeof(encoded_chat))
            || !url_encode(message, encoded_message, sizeof(encoded_message)))
        return 0;

    rv = snprintf(curl_config, sizeof(curl_config),
            "silent\n"
            "show-error\n"
            "fail\n"
            "connect-timeout = 3\n"
            "max-time = 5\n"
            "request = \"POST\"\n"
            "url = \"https://api.telegram.org/bot%s/sendMessage\"\n"
            "header = \"Content-Type: application/x-www-form-urlencoded\"\n"
            "data = \"chat_id=%s&text=%s\"\n",
            token, encoded_chat, encoded_message);
    if(rv < 0 || (size_t)rv >= sizeof(curl_config))
        return 0;

    rv = run_curl_config(curl_config);
    memset(curl_config, 0, sizeof(curl_config));
    return rv;
}

static void
format_time(const time_t timestamp, char *output, const size_t output_size)
{
    struct tm local_tm;

    if(localtime_r(&timestamp, &local_tm) == NULL
            || strftime(output, output_size, "%Y-%m-%d %H:%M:%S %z",
                &local_tm) == 0)
        strlcpy(output, "unknown", output_size);
}

static int
telegram_is_configured(const fko_srv_options_t *opts)
{
    return opts != NULL
        && opts->config[CONF_PORTGUARD_TG_BOT_TOKEN] != NULL
        && opts->config[CONF_PORTGUARD_TG_CHAT_ID] != NULL;
}

static int
send_test_notification(const fko_srv_options_t *opts)
{
    char hostname[MAX_HOSTNAME_LEN] = {0};
    char current_time[64] = {0};
    char message[TG_MESSAGE_MAX_LEN] = {0};
    time_t now;

    if(!telegram_is_configured(opts))
        return 0;
    if(gethostname(hostname, sizeof(hostname) - 1) != 0)
        strlcpy(hostname, "unknown", sizeof(hostname));
    time(&now);
    format_time(now, current_time, sizeof(current_time));
    snprintf(message, sizeof(message),
            "PortGuard Telegram notifications configured\n"
            "Server: %s\n"
            "Time: %s",
            hostname, current_time);
    return send_message(opts->config[CONF_PORTGUARD_TG_BOT_TOKEN],
            opts->config[CONF_PORTGUARD_TG_CHAT_ID], message);
}

void
telegram_notify_access(const fko_srv_options_t *opts,
        const spa_data_t *spadat, const time_t opened_at,
        const time_t expires_at)
{
    char hostname[MAX_HOSTNAME_LEN] = {0};
    char opened_text[64] = {0};
    char expires_text[64] = {0};
    char message[TG_MESSAGE_MAX_LEN] = {0};
    unsigned long interval = 0;
    pid_t pid;

    if(!telegram_is_configured(opts) || spadat == NULL)
        return;

    interval = strtoul(opts->config[CONF_PORTGUARD_TG_NOTIFY_INTERVAL],
            NULL, 10);
    if(interval > 0 && last_notification_at > 0
            && opened_at >= last_notification_at
            && (unsigned long)(opened_at - last_notification_at) < interval)
    {
        log_msg(LOG_DEBUG, "Telegram access notification skipped by %lu-second interval",
                interval);
        return;
    }
    last_notification_at = opened_at;

    if(gethostname(hostname, sizeof(hostname) - 1) != 0)
        strlcpy(hostname, "unknown", sizeof(hostname));
    format_time(opened_at, opened_text, sizeof(opened_text));
    format_time(expires_at, expires_text, sizeof(expires_text));

    snprintf(message, sizeof(message),
            "PortGuard access granted\n"
            "Server: %s\n"
            "Source IP: %s\n"
            "Packet IP: %s\n"
            "User: %s\n"
            "Access: %s\n"
            "Opened at: %s\n"
            "Expires at: %s\n"
            "Timeout: %u seconds",
            hostname,
            spadat->use_src_ip == NULL ? "unknown" : spadat->use_src_ip,
            spadat->pkt_source_ip[0] == '\0' ? "unknown" : spadat->pkt_source_ip,
            spadat->username == NULL ? "unknown" : spadat->username,
            spadat->spa_message_remain[0] == '\0'
                ? "unknown" : spadat->spa_message_remain,
            opened_text, expires_text, spadat->fw_access_timeout);

    pid = fork();
    if(pid == 0)
    {
        int sent;
        signal(SIGCHLD, SIG_DFL);
        sent = send_message(opts->config[CONF_PORTGUARD_TG_BOT_TOKEN],
                opts->config[CONF_PORTGUARD_TG_CHAT_ID], message);
        if(!sent)
            log_msg(LOG_WARNING, "Could not send Telegram access notification");
        _exit(sent ? EXIT_SUCCESS : EXIT_FAILURE);
    }
    if(pid < 0)
        log_msg(LOG_WARNING, "Could not fork Telegram notification worker: %s",
                strerror(errno));
}

static int
config_line_matches(const char *line, const char *name)
{
    const char *cursor = line;
    size_t name_len = strlen(name);

    while(*cursor == ' ' || *cursor == '\t')
        cursor++;
    if(*cursor == '#')
        return 0;
    return strncmp(cursor, name, name_len) == 0
        && IS_CONFIG_PARAM_DELIMITER(cursor[name_len]);
}

static int
write_telegram_config(const char *config_file, const char *token,
        const char *chat_id, const unsigned long interval)
{
    char line[MAX_LINE_LEN] = {0};
    char temp_path[MAX_PATH_LEN] = {0};
    struct stat source_stat;
    FILE *source = NULL, *dest = NULL;
    int temp_fd = -1, rv = 0;

    source = fopen(config_file, "r");
    if(source == NULL || fstat(fileno(source), &source_stat) != 0
            || !S_ISREG(source_stat.st_mode))
        goto cleanup;

    if(snprintf(temp_path, sizeof(temp_path), "%s.telegram.XXXXXX",
                config_file) >= (int)sizeof(temp_path))
        goto cleanup;
    temp_fd = mkstemp(temp_path);
    if(temp_fd < 0 || fchmod(temp_fd, S_IRUSR | S_IWUSR) != 0
            || fchown(temp_fd, source_stat.st_uid, source_stat.st_gid) != 0)
        goto cleanup;

    dest = fdopen(temp_fd, "w");
    if(dest == NULL)
        goto cleanup;
    temp_fd = -1;

    while(fgets(line, sizeof(line), source) != NULL)
    {
        if(config_line_matches(line, "PORTGUARD_TG_BOT_TOKEN")
                || config_line_matches(line, "PORTGUARD_TG_CHAT_ID")
                || config_line_matches(line, "PORTGUARD_TG_NOTIFY_INTERVAL"))
            continue;
        if(fputs(line, dest) == EOF)
            goto cleanup;
    }
    if(ferror(source))
        goto cleanup;

    if(token != NULL)
    {
        if(fprintf(dest,
                "\nPORTGUARD_TG_BOT_TOKEN       %s;\n"
                "PORTGUARD_TG_CHAT_ID          %s;\n"
                "PORTGUARD_TG_NOTIFY_INTERVAL  %lu;\n",
                token, chat_id, interval) < 0)
            goto cleanup;
    }
    if(fflush(dest) != 0 || fsync(fileno(dest)) != 0 || fclose(dest) != 0)
    {
        dest = NULL;
        goto cleanup;
    }
    dest = NULL;
    if(rename(temp_path, config_file) != 0)
        goto cleanup;
    temp_path[0] = '\0';
    rv = 1;

cleanup:
    if(source != NULL)
        fclose(source);
    if(dest != NULL)
        fclose(dest);
    if(temp_fd >= 0)
        close(temp_fd);
    if(temp_path[0] != '\0')
        remove(temp_path);
    return rv;
}

static int
read_console_line(char *buf, const size_t size)
{
    fflush(stdout);
    if(fgets(buf, size, stdin) == NULL)
        return 0;
    buf[strcspn(buf, "\r\n")] = '\0';
    return 1;
}

static int
read_console_secret(char *buf, const size_t size)
{
    struct termios original, hidden;
    int echo_disabled = 0;
    int rv;

    if(isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &original) == 0)
    {
        hidden = original;
        hidden.c_lflag &= ~ECHO;
#ifdef ECHONL
        hidden.c_lflag &= ~ECHONL;
#endif
        if(tcsetattr(STDIN_FILENO, TCSANOW, &hidden) == 0)
            echo_disabled = 1;
    }

    rv = read_console_line(buf, size);
    if(echo_disabled)
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &original);
        printf("\n");
    }
    return rv;
}

static void
replace_config_value(fko_srv_options_t *opts, const int index,
        const char *value)
{
    if(opts->config[index] != NULL)
    {
        if(index == CONF_PORTGUARD_TG_BOT_TOKEN)
            memset(opts->config[index], 0, strlen(opts->config[index]));
        free(opts->config[index]);
        opts->config[index] = NULL;
    }
    if(value != NULL)
    {
        opts->config[index] = calloc(1, strlen(value) + 1);
        if(opts->config[index] != NULL)
            strlcpy(opts->config[index], value, strlen(value) + 1);
    }
}

int
telegram_configure_console(fko_srv_options_t *opts)
{
    char token[PORTGUARD_TG_TOKEN_MAX_LEN] = {0};
    char chat_id[PORTGUARD_TG_CHAT_ID_MAX_LEN] = {0};
    char interval_text[32] = {0};
    char answer[16] = {0};
    char *endptr = NULL;
    unsigned long interval = 0;
    int enabled = telegram_is_configured(opts);

    printf("\nTelegram Notifications\n");
    printf("======================\n");
    printf("Status: %s\n", enabled ? "configured" : "disabled");
    printf("Enter 'disable' as the bot token to disable notifications.\n");
    printf("Bot token%s: ", enabled ? " (press Enter to keep current)" : "");
    if(!read_console_secret(token, sizeof(token)))
        goto canceled;

    if(strcasecmp(token, "disable") == 0)
    {
        printf("Disable Telegram notifications? (y/n): ");
        if(!read_console_line(answer, sizeof(answer))
                || (answer[0] != 'y' && answer[0] != 'Y'))
            goto canceled;
        if(!write_telegram_config(opts->config[CONF_CONFIG_FILE], NULL, NULL, 0))
        {
            printf("Failed to update %s: %s\n",
                    opts->config[CONF_CONFIG_FILE], strerror(errno));
            goto canceled;
        }
        replace_config_value(opts, CONF_PORTGUARD_TG_BOT_TOKEN, NULL);
        replace_config_value(opts, CONF_PORTGUARD_TG_CHAT_ID, NULL);
        replace_config_value(opts, CONF_PORTGUARD_TG_NOTIFY_INTERVAL,
                DEF_PORTGUARD_TG_NOTIFY_INTERVAL);
        printf("Telegram notifications disabled. Restart fwknopd to apply.\n");
        memset(token, 0, sizeof(token));
        return 1;
    }

    if(token[0] == '\0' && enabled)
        strlcpy(token, opts->config[CONF_PORTGUARD_TG_BOT_TOKEN], sizeof(token));
    if(!telegram_bot_token_is_valid(token))
    {
        printf("Invalid bot token. Expected the BotFather token format.\n");
        goto canceled;
    }

    printf("Chat ID%s: ", enabled ? " (press Enter to keep current)" : "");
    if(!read_console_line(chat_id, sizeof(chat_id)))
        goto canceled;
    if(chat_id[0] == '\0' && enabled)
        strlcpy(chat_id, opts->config[CONF_PORTGUARD_TG_CHAT_ID],
                sizeof(chat_id));
    if(!telegram_chat_id_is_valid(chat_id))
    {
        printf("Invalid chat ID. Use a numeric chat ID or @channel_username.\n");
        goto canceled;
    }

    printf("Minimum notification interval in seconds [0 = every knock, current %s]: ",
            opts->config[CONF_PORTGUARD_TG_NOTIFY_INTERVAL]);
    if(!read_console_line(interval_text, sizeof(interval_text)))
        goto canceled;
    if(interval_text[0] == '\0')
        strlcpy(interval_text, opts->config[CONF_PORTGUARD_TG_NOTIFY_INTERVAL],
                sizeof(interval_text));
    errno = 0;
    interval = strtoul(interval_text, &endptr, 10);
    if(errno != 0 || endptr == interval_text || *endptr != '\0'
            || interval > RCHK_MAX_TG_NOTIFY_INTERVAL)
    {
        printf("Invalid interval. Use 0-%d seconds.\n",
                RCHK_MAX_TG_NOTIFY_INTERVAL);
        goto canceled;
    }

    printf("Save Telegram configuration for chat %s with interval %lu? (y/n): ",
            chat_id, interval);
    if(!read_console_line(answer, sizeof(answer))
            || (answer[0] != 'y' && answer[0] != 'Y'))
        goto canceled;
    if(!write_telegram_config(opts->config[CONF_CONFIG_FILE], token, chat_id,
                interval))
    {
        printf("Failed to update %s: %s\n",
                opts->config[CONF_CONFIG_FILE], strerror(errno));
        goto canceled;
    }

    replace_config_value(opts, CONF_PORTGUARD_TG_BOT_TOKEN, token);
    replace_config_value(opts, CONF_PORTGUARD_TG_CHAT_ID, chat_id);
    snprintf(interval_text, sizeof(interval_text), "%lu", interval);
    replace_config_value(opts, CONF_PORTGUARD_TG_NOTIFY_INTERVAL, interval_text);
    printf("Telegram configuration saved. Restart fwknopd to apply it.\n");
    printf("Send a test notification now? (y/n): ");
    if(read_console_line(answer, sizeof(answer))
            && (answer[0] == 'y' || answer[0] == 'Y'))
    {
        if(send_test_notification(opts))
            printf("Telegram test notification sent successfully.\n");
        else
            printf("Telegram test notification failed. Check the token, chat ID, network, and curl installation.\n");
    }
    memset(token, 0, sizeof(token));
    return 1;

canceled:
    memset(token, 0, sizeof(token));
    printf("Telegram configuration was not changed.\n");
    return 0;
}
