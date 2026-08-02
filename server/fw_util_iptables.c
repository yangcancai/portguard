/**
 * \file server/fw_util_iptables.c
 *
 * \brief Fwknop routines for managing iptables firewall rules.
 */

/*  Fwknop is developed primarily by the people listed in the file 'AUTHORS'.
 *  Copyright (C) 2009-2015 fwknop developers and contributors. For a full
 *  list of contributors, see the file 'CREDITS'.
 *
 *  License (GNU General Public License):
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *****************************************************************************
*/

#include "fwknopd_common.h"

#ifdef FIREWALL_IPTABLES

#include "fw_util.h"
#include "utils.h"
#include "log_msg.h"
#include "extcmd.h"
#include "access.h"

static struct fw_config fwc;
static char   cmd_buf[CMD_BUFSIZE];
static char   err_buf[CMD_BUFSIZE];
static char   cmd_out[STANDARD_CMD_OUT_BUFSIZE];

/* assume 'iptables -C' is offered since only older versions
 * don't have this (see ipt_chk_support()).
*/
static int have_ipt_chk_support = 1;

static void
zero_cmd_buffers(void)
{
    memset(cmd_buf, 0x0, CMD_BUFSIZE);
    memset(err_buf, 0x0, CMD_BUFSIZE);
    memset(cmd_out, 0x0, STANDARD_CMD_OUT_BUFSIZE);
}

static int pid_status = 0;

static int
rule_exists_no_chk_support(const fko_srv_options_t * const opts,
        const struct fw_chain * const fwc,
        const unsigned int proto,
        const char * const srcip,
        const char * const dstip,
        const unsigned int port,
        const char * const natip,
        const unsigned int nat_port,
        const unsigned int exp_ts)
{
    int     rule_exists=0;
    char    ipt_line_buf[CMD_BUFSIZE]    = {0};
    char    target_search[CMD_BUFSIZE]   = {0};
    char    proto_search[CMD_BUFSIZE]    = {0};
    char    srcip_search[CMD_BUFSIZE]    = {0};
    char    dstip_search[CMD_BUFSIZE]    = {0};
    char    natip_search[CMD_BUFSIZE]    = {0};
    char    port_search[CMD_BUFSIZE]     = {0};
    char    nat_port_search[CMD_BUFSIZE] = {0};
    char    exp_ts_search[CMD_BUFSIZE]   = {0};
    char    *ndx = NULL;

#if CODE_COVERAGE
    /* If we're maximizing code coverage, then exercise the run_extcmd_write()
     * function which is normally only used for the PF firewall. This is to
     * maximize code coverage in conjunction with the test suite, and is never
     * compiled in for a production release of fwknop.
    */
    if(run_extcmd_write("/bin/grep -v test", "/bin/echo test", &pid_status, opts) == 0)
        log_msg(LOG_WARNING, "[ignore] Code coverage: Executed command");
#endif

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
        opts->fw_config->fw_command,
        fwc->table,
        fwc->to_chain
    );

    if(proto == IPPROTO_TCP)
        snprintf(proto_search, CMD_BUFSIZE-1, " tcp ");
    else if(proto == IPPROTO_UDP)
        snprintf(proto_search, CMD_BUFSIZE-1, " udp ");
    else if(proto == IPPROTO_ICMP)
        snprintf(proto_search, CMD_BUFSIZE-1, " icmp ");
    else
        snprintf(proto_search, CMD_BUFSIZE-1, " %u ", proto);

    snprintf(port_search, CMD_BUFSIZE-1, "dpt:%u ", port);
    snprintf(nat_port_search, CMD_BUFSIZE-1, ":%u", nat_port);
    snprintf(target_search, CMD_BUFSIZE-1, " %s ", fwc->target);

    if (srcip != NULL)
        snprintf(srcip_search, CMD_BUFSIZE-1, " %s ", srcip);

    if (dstip != NULL)
        snprintf(dstip_search, CMD_BUFSIZE-1, " %s ", dstip);

    if (natip != NULL)
        snprintf(dstip_search, CMD_BUFSIZE-1, " to:%s", natip);

    snprintf(exp_ts_search, CMD_BUFSIZE-1, "%u ", exp_ts);

    /* search for each of the substrings - the rule expiration time is the
     * primary search method
    */
    if(search_extcmd_getline(cmd_buf, ipt_line_buf,
                CMD_BUFSIZE, NO_TIMEOUT, exp_ts_search, &pid_status, opts))
    {
        chop_newline(ipt_line_buf);
        /* we have an iptables policy rule that matches the
         * expiration time, so make sure this rule matches the
         * other fields too. If not, then it is for different
         * access requested by a separate SPA packet.
        */
        if(((proto == ANY_PROTO) ? 1 : (strstr(ipt_line_buf, proto_search) != NULL))
            && ((srcip == NULL) ? 1 : (strstr(ipt_line_buf, srcip_search) != NULL))
            && ((dstip == NULL) ? 1 : (strstr(ipt_line_buf, dstip_search) != NULL))
            && ((natip == NULL) ? 1 : (strstr(ipt_line_buf, natip_search) != NULL))
            && (strstr(ipt_line_buf, target_search) != NULL)
            && ((port == ANY_PORT) ? 1 : (strstr(ipt_line_buf, port_search) != NULL)))
        {
            rule_exists = 1;
        }
    }

    /* If there is a nat port, we have to qualify it as part
     * of the 'to:<ip>:<port>' portion of the rule (at the end)
    */
    if(rule_exists && nat_port != NAT_ANY_PORT)
    {
        ndx = strstr(ipt_line_buf, " to:");
        /* Make sure there isn't a duplicate " to:" string (i.e. if someone
         * was trying to be tricky with the iptables comment match).
        */
        if(ndx != NULL && (strstr((ndx+strlen(" to:")), " to:") == NULL))
        {
            ndx = strstr((ndx+strlen(" to:")), nat_port_search);
            if (ndx == NULL)
            {
                rule_exists = 0;
            }
            else if((*(ndx+strlen(nat_port_search)) != '\0')
                    && (*(ndx+strlen(nat_port_search)) != ' '))
            {
                rule_exists = 0;
            }
        }
        else
        {
            rule_exists = 0;
        }
    }

    if(rule_exists)
        log_msg(LOG_DEBUG,
                "rule_exists_no_chk_support() %s %u -> %s expires: %u rule already exists",
                proto_search, port, srcip, exp_ts);
    else
        log_msg(LOG_DEBUG,
                "rule_exists_no_chk_support() %s %u -> %s expires: %u rule does not exist",
                proto_search, port, srcip, exp_ts);

   return(rule_exists);
}

static int
rule_exists_chk_support(const fko_srv_options_t * const opts,
        const char * const chain, const char * const rule)
{
    int     rule_exists = 0;
    int     res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_CHK_RULE_ARGS,
            opts->fw_config->fw_command, chain, rule);

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG,
            "rule_exists_chk_support() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res) && strlen(err_buf))
    {
        log_msg(LOG_DEBUG,
                "rule_exists_chk_support() Rule : '%s' in %s does not exist",
                rule, chain);
    }
    else
    {
        rule_exists = 1;
        log_msg(LOG_DEBUG,
                "rule_exists_chk_support() Rule : '%s' in %s already exists",
                rule, chain);
    }

    return(rule_exists);
}

static int
rule_exists(const fko_srv_options_t * const opts,
        const struct fw_chain * const fwc,
        const char * const rule,
        const unsigned int proto,
        const char * const srcip,
        const char * const dstip,
        const unsigned int port,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int exp_ts)
{
    int rule_exists = 0;

    if(have_ipt_chk_support == 1)
        rule_exists = rule_exists_chk_support(opts, fwc->to_chain, rule);
    else
        rule_exists = rule_exists_no_chk_support(opts, fwc, proto, srcip,
                (opts->fw_config->use_destination ? dstip : NULL), port,
                nat_ip, nat_port, exp_ts);

    if(rule_exists == 1)
        log_msg(LOG_DEBUG, "rule_exists() Rule : '%s' in %s already exists",
                rule, fwc->to_chain);
    else
        log_msg(LOG_DEBUG, "rule_exists() Rule : '%s' in %s does not exist",
                rule, fwc->to_chain);

    return(rule_exists);
}

static void
ipt_chk_support(const fko_srv_options_t * const opts)
{
    int               res = 1;
    struct fw_chain  *in_chain = &(opts->fw_config->chain[IPT_INPUT_ACCESS]);

    zero_cmd_buffers();

    /* Add a harmless rule to the iptables INPUT chain and see if iptables
     * supports '-C' to check for it.  Set "have_ipt_chk_support" accordingly,
     * delete the rule, and return.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_TMP_CHK_RULE_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        1,   /* first rule */
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "ipt_chk_support() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    zero_cmd_buffers();

    /* Now see if '-C' works - any output indicates failure
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_TMP_VERIFY_CHK_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "ipt_chk_support() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res) && strlen(err_buf))
    {
        log_msg(LOG_DEBUG, "ipt_chk_support() -C not supported");
        have_ipt_chk_support = 0;
    }
    else
    {
        log_msg(LOG_DEBUG, "ipt_chk_support() -C supported");
        have_ipt_chk_support = 1;
    }

    /* Delete the tmp rule
    */
    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        1
    );
    run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    return;
}

static int
comment_match_exists(const fko_srv_options_t * const opts)
{
    int               res = 1;
    char             *ndx = NULL;
    struct fw_chain  *in_chain  = &(opts->fw_config->chain[IPT_INPUT_ACCESS]);

    zero_cmd_buffers();

    /* Add a harmless rule to the iptables INPUT chain that uses the comment
     * match and make sure it exists.  If not, return zero.  Otherwise, delete
     * the rule and return true.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_TMP_COMMENT_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain,
        1,   /* first rule */
        in_chain->target
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "comment_match_exists() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
        opts->fw_config->fw_command,
        in_chain->table,
        in_chain->from_chain
    );

    res = run_extcmd(cmd_buf, cmd_out, STANDARD_CMD_OUT_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(cmd_out);

    if(!EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_ERR, "comment_match_exists() Error %i from cmd:'%s': %s",
                res, cmd_buf, cmd_out);

    ndx = strstr(cmd_out, TMP_COMMENT);
    if(ndx == NULL)
        res = 0;  /* did not find the tmp comment */
    else
        res = 1;

    if(res == 1)
    {
        /* Delete the tmp comment rule
        */
        zero_cmd_buffers();

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
            opts->fw_config->fw_command,
            in_chain->table,
            in_chain->from_chain,
            1
        );
        run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    }

    return res;
}

static int
add_jump_rule(const fko_srv_options_t * const opts, const int chain_num)
{
    int res = 0, rv = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_JUMP_RULE_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].from_chain,
        fwc.chain[chain_num].jump_rule_pos,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);

    log_msg(LOG_DEBUG, "add_jump_rule() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_INFO, "Added jump rule from chain: %s to chain: %s",
            fwc.chain[chain_num].from_chain,
            fwc.chain[chain_num].to_chain);
        rv = 1;
    }
    else
        log_msg(LOG_ERR, "add_jump_rule() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return rv;
}

static int
chain_exists(const fko_srv_options_t * const opts, const int chain_num)
{
    int res = 0;

    zero_cmd_buffers();

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_CHAIN_EXISTS_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
            WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "chain_exists() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
        log_msg(LOG_DEBUG, "'%s' table '%s' chain exists",
            fwc.chain[chain_num].table,
            fwc.chain[chain_num].to_chain);
    else
        log_msg(LOG_ERR, "chain_exists() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return res;
}

static int
jump_rule_exists_chk_support(const fko_srv_options_t * const opts, const int chain_num)
{
    int    exists = 0;
    char   rule_buf[CMD_BUFSIZE] = {0};

    snprintf(rule_buf, CMD_BUFSIZE-1, IPT_CHK_JUMP_RULE_ARGS,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    if(rule_exists_chk_support(opts, fwc.chain[chain_num].from_chain, rule_buf) == 1)
    {
        log_msg(LOG_DEBUG, "jump_rule_exists_chk_support() jump rule found");
        exists = 1;
    }
    else
        log_msg(LOG_DEBUG, "jump_rule_exists_chk_support() jump rule not found");

    return exists;
}

static int
jump_rule_exists_no_chk_support(const fko_srv_options_t * const opts,
        const int chain_num)
{
    int     exists = 0;
    char    chain_search[CMD_BUFSIZE] = {0};

    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].from_chain
    );

    /* include spaces on either side as produced by 'iptables -L' output
    */
    snprintf(chain_search, CMD_BUFSIZE-1, " %s ",
        fwc.chain[chain_num].to_chain);

    if(search_extcmd(cmd_buf, WANT_STDERR,
                NO_TIMEOUT, chain_search, &pid_status, opts) > 0)
        exists = 1;

    if(exists)
        log_msg(LOG_DEBUG, "jump_rule_exists_no_chk_support() jump rule found");
    else
        log_msg(LOG_DEBUG, "jump_rule_exists_no_chk_support() jump rule not found");

   return(exists);
}

static int
jump_rule_exists(const fko_srv_options_t * const opts, const int chain_num)
{
    int    exists = 0;

    if(have_ipt_chk_support == 1)
        exists = jump_rule_exists_chk_support(opts, chain_num);
    else
        exists = jump_rule_exists_no_chk_support(opts, chain_num);

    return exists;
}

/* Print all firewall rules currently instantiated by the running fwknopd
 * daemon to stdout.
*/
int
fw_dump_rules(const fko_srv_options_t * const opts)
{
    int     i, res, got_err = 0;

    struct fw_chain *ch = opts->fw_config->chain;

    if (opts->fw_list_all == 1)
    {
        fprintf(stdout, "Listing all iptables rules in applicable tables...\n");
        fflush(stdout);

        for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
        {
            if(fwc.chain[i].target[0] == '\0')
                continue;

            zero_cmd_buffers();

            /* Create the list command
            */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_ALL_RULES_ARGS,
                opts->fw_config->fw_command,
                ch[i].table
            );

            res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                        NO_TIMEOUT, &pid_status, opts);

            log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
                cmd_buf, res);

            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_ERR, "fw_dump_rules() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);
                got_err++;
            }
        }
    }
    else
    {
        fprintf(stdout, "Listing rules in fwknopd iptables chains...\n");
        fflush(stdout);

        for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
        {
            if(fwc.chain[i].target[0] == '\0')
                continue;

            zero_cmd_buffers();

            /* Create the list command
            */
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
                opts->fw_config->fw_command,
                ch[i].table,
                ch[i].to_chain
            );

            fprintf(stdout, "\n");
            fflush(stdout);

            res = run_extcmd(cmd_buf, NULL, 0, NO_STDERR,
                        NO_TIMEOUT, &pid_status, opts);

            log_msg(LOG_DEBUG, "fw_dump_rules() CMD: '%s' (res: %d)",
                cmd_buf, res);

            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_ERR, "fw_dump_rules() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);
                got_err++;
            }
        }
    }

    return(got_err);
}

/* Quietly flush and delete all fwknop custom chains.
*/
static void
delete_all_chains(const fko_srv_options_t * const opts)
{
    int     i, res, cmd_ctr = 0;

    for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        /* First look for a jump rule to this chain and remove it if it
         * is there.
        */
        cmd_ctr = 0;
        while(cmd_ctr < CMD_LOOP_TRIES && (jump_rule_exists(opts, i) == 1))
        {
            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_JUMP_RULE_ARGS,
                fwc.fw_command,
                fwc.chain[i].table,
                fwc.chain[i].from_chain,
                fwc.chain[i].to_chain
            );

            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                    WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
            chop_newline(err_buf);

            log_msg(LOG_DEBUG, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

            /* Expect full success on this */
            if(! EXTCMD_IS_SUCCESS(res))
                log_msg(LOG_ERR, "delete_all_chains() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);

            cmd_ctr++;
        }

        zero_cmd_buffers();

        /* Now flush and remove the chain.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_FLUSH_CHAIN_ARGS,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain
        );

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
        chop_newline(err_buf);

        log_msg(LOG_DEBUG, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "delete_all_chains() Error %i from cmd:'%s': %s",
                    res, cmd_buf, err_buf);

        zero_cmd_buffers();

        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_CHAIN_ARGS,
            fwc.fw_command,
            fwc.chain[i].table,
            fwc.chain[i].to_chain
        );

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
        chop_newline(err_buf);

        log_msg(LOG_DEBUG, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
            cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "delete_all_chains() Error %i from cmd:'%s': %s",
                    res, cmd_buf, err_buf);
    }

#if USE_LIBNETFILTER_QUEUE
    if(opts->enable_nfq_capture)
    {
        zero_cmd_buffers();

        /* Delete the rule to direct traffic to the NFQ chain.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            "INPUT",
            1
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

        zero_cmd_buffers();

        /* Flush the NFQ chain
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_FLUSH_CHAIN_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            opts->config[CONF_NFQ_CHAIN]
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);

        zero_cmd_buffers();

        /* Delete the NF_QUEUE chains and rules
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_CHAIN_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            opts->config[CONF_NFQ_CHAIN]
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "delete_all_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
    }
#endif
    return;
}

static int
create_chain(const fko_srv_options_t * const opts, const int chain_num)
{
    int res = 0, rv = 0;

    zero_cmd_buffers();

    /* Create the custom chain.
    */
    snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_NEW_CHAIN_ARGS,
        fwc.fw_command,
        fwc.chain[chain_num].table,
        fwc.chain[chain_num].to_chain
    );

    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "create_chain() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    /* Expect full success on this */
    if(EXTCMD_IS_SUCCESS(res))
        rv = 1;
    else
        log_msg(LOG_ERR, "create_chain() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return rv;
}

static int
mk_chain(const fko_srv_options_t * const opts, const int chain_num)
{
    int err = 0;

    /* Make sure the required chain and jump rule exist
    */
    if(! chain_exists(opts, chain_num))
        if(! create_chain(opts, chain_num))
            err++;

    if (! jump_rule_exists(opts, chain_num))
        if(! add_jump_rule(opts, chain_num))
            err++;

    return err;
}

/* Create the fwknop custom chains (at least those that are configured).
*/
static int
create_fw_chains(const fko_srv_options_t * const opts)
{
    int     i, got_err = 0;
#if USE_LIBNETFILTER_QUEUE
    int     res = 0;
#endif

    for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        if(fwc.chain[i].target[0] == '\0')
            continue;

        got_err += mk_chain(opts, i);
    }

#if USE_LIBNETFILTER_QUEUE
    if(opts->enable_nfq_capture)
    {
        zero_cmd_buffers();

        /* Create the NF_QUEUE chains and rules
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_NEW_CHAIN_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            opts->config[CONF_NFQ_CHAIN]
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                         NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "create_fw_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }

        zero_cmd_buffers();

        /* Create the rule to direct traffic to the NFQ chain.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_ADD_JUMP_RULE_ARGS,
            fwc.fw_command,
            opts->config[CONF_NFQ_TABLE],
            "INPUT",
            1,
            opts->config[CONF_NFQ_CHAIN]
        );
        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                         NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "create_fw_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }

        zero_cmd_buffers();

        /* Create the rule to direct SPA packets to the queue.
         * If an interface is specified use the "_WITH_IF" version
         * of the command.
        */
        if(strlen(opts->config[CONF_NFQ_INTERFACE]) > 0)
        {
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_NFQ_ADD_ARGS_WITH_IF,
                fwc.fw_command,
                opts->config[CONF_NFQ_TABLE],
                opts->config[CONF_NFQ_CHAIN],
                opts->config[CONF_NFQ_INTERFACE],
                opts->config[CONF_NFQ_PORT],
                opts->config[CONF_NFQ_QUEUE_NUMBER]
            );
        }
        else
        {
            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_NFQ_ADD_ARGS,
                fwc.fw_command,
                opts->config[CONF_NFQ_TABLE],
                opts->config[CONF_NFQ_CHAIN],
                opts->config[CONF_NFQ_PORT],
                opts->config[CONF_NFQ_QUEUE_NUMBER]
            );
        }

        res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);

        if (opts->verbose)
            log_msg(LOG_INFO, "create_fw_chains() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

        /* Expect full success on this */
        if(! EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR, "Error %i from cmd:'%s': %s", res, cmd_buf, err_buf);
            got_err++;
        }
    }
#endif
    return(got_err);
}

static int
set_fw_chain_conf(const int type, const char * const conf_str)
{
    int i, j, is_err;
    char tbuf[MAX_LINE_LEN]  = {0};
    const char *ndx          = conf_str;

    char *chain_fields[FW_NUM_CHAIN_FIELDS];

    struct fw_chain *chain = &(fwc.chain[type]);

    if(conf_str == NULL)
    {
        log_msg(LOG_ERR, "[*] NULL conf_str");
        return 0;
    }

    chain->type = type;

    if(ndx != NULL)
        chain_fields[0] = tbuf;

    i = 0;
    j = 1;
    while(*ndx != '\0')
    {
        if(*ndx != ' ')
        {
            if(*ndx == ',')
            {
                tbuf[i] = '\0';
                chain_fields[j++] = &(tbuf[++i]);
            }
            else
                tbuf[i++] = *ndx;
        }
        if(*ndx != '\0'
                && *ndx != ' '
                && *ndx != ','
                && *ndx != '_'
                && isalnum(*ndx) == 0)
        {
            log_msg(LOG_ERR, "[*] Custom chain config parse error: "
                "invalid character '%c' for chain type %i, "
                "line: %s", *ndx, type, conf_str);
            return 0;
        }
        ndx++;
    }

    /* Sanity check - j should be the number of chain fields
     * (excluding the type).
    */
    if(j != FW_NUM_CHAIN_FIELDS)
    {
        log_msg(LOG_ERR, "[*] Custom chain config parse error: "
            "wrong number of fields for chain type %i, "
            "line: %s", type, conf_str);
        return 0;
    }

    /* Pull and set Target */
    strlcpy(chain->target, chain_fields[0], sizeof(chain->target));

    /* Pull and set Table */
    strlcpy(chain->table, chain_fields[1], sizeof(chain->table));

    /* Pull and set From_chain */
    strlcpy(chain->from_chain, chain_fields[2], sizeof(chain->from_chain));

    /* Pull and set Jump_rule_position */
    chain->jump_rule_pos = strtol_wrapper(chain_fields[3],
            0, RCHK_MAX_IPT_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid jump rule position in Line: %s",
            conf_str);
        return 0;
    }

    /* Pull and set To_chain */
    strlcpy(chain->to_chain, chain_fields[4], sizeof(chain->to_chain));

    /* Pull and set to_chain rule position */
    chain->rule_pos = strtol_wrapper(chain_fields[5],
            0, RCHK_MAX_IPT_RULE_NUM, NO_EXIT_UPON_ERR, &is_err);
    if(is_err != FKO_SUCCESS)
    {
        log_msg(LOG_ERR, "[*] invalid to_chain rule position in Line: %s",
            conf_str);
        return 0;
    }
    return 1;
}

int
fw_config_init(fko_srv_options_t * const opts)
{
    memset(&fwc, 0x0, sizeof(struct fw_config));

    /* Set our firewall exe command path (iptables in most cases).
    */
    strlcpy(fwc.fw_command, opts->config[CONF_FIREWALL_EXE], sizeof(fwc.fw_command));

#if HAVE_LIBFIU
    fiu_return_on("fw_config_init", 0);
#endif

    /* Pull the fwknop chain config info and setup our internal
     * config struct.  The IPT_INPUT is the only one that is
     * required. The rest are optional.
    */
    if(set_fw_chain_conf(IPT_INPUT_ACCESS, opts->config[CONF_IPT_INPUT_ACCESS]) != 1)
        return 0;

    /* The FWKNOP_OUTPUT_ACCESS requires ENABLE_IPT_OUTPUT_ACCESS == Y
    */
    if(strncasecmp(opts->config[CONF_ENABLE_IPT_OUTPUT], "Y", 1)==0)
        if(set_fw_chain_conf(IPT_OUTPUT_ACCESS, opts->config[CONF_IPT_OUTPUT_ACCESS]) != 1)
            return 0;

    /* The remaining access chains require ENABLE_IPT_FORWARDING = Y
    */
    if(strncasecmp(opts->config[CONF_ENABLE_IPT_FORWARDING], "Y", 1)==0
            || strncasecmp(opts->config[CONF_ENABLE_IPT_LOCAL_NAT], "Y", 1)==0)

    {
        if(set_fw_chain_conf(IPT_FORWARD_ACCESS, opts->config[CONF_IPT_FORWARD_ACCESS]) != 1)
            return 0;

        if(set_fw_chain_conf(IPT_DNAT_ACCESS, opts->config[CONF_IPT_DNAT_ACCESS]) != 1)
            return 0;

        /* Requires ENABLE_IPT_SNAT = Y
        */
        if(strncasecmp(opts->config[CONF_ENABLE_IPT_SNAT], "Y", 1)==0)
        {
            /* Support both SNAT and MASQUERADE - this will be controlled
             * via the access.conf configuration for individual rules
            */
            if(set_fw_chain_conf(IPT_MASQUERADE_ACCESS,
                        opts->config[CONF_IPT_MASQUERADE_ACCESS]) != 1)
                return 0;

            if(set_fw_chain_conf(IPT_SNAT_ACCESS,
                        opts->config[CONF_IPT_SNAT_ACCESS]) != 1)
                return 0;
        }
    }

    if(strncasecmp(opts->config[CONF_ENABLE_DESTINATION_RULE], "Y", 1)==0)
    {
        fwc.use_destination = 1;
    }

    /* Let us find it via our opts struct as well.
    */
    opts->fw_config = &fwc;

    return 1;
}

int
fw_initialize(const fko_srv_options_t * const opts)
{
    int res = 1;

    /* See if iptables offers the '-C' argument (older versions don't).  If not,
     * then switch to parsing iptables -L output to find rules.
    */
    if(opts->ipt_disable_check_support)
        have_ipt_chk_support = 0;
    else
        ipt_chk_support(opts);

    /* Flush the chains (just in case) so we can start fresh.
    */
    if(strncasecmp(opts->config[CONF_FLUSH_IPT_AT_INIT], "Y", 1) == 0)
        delete_all_chains(opts);

    /* Now create any configured chains.
    */
    if(create_fw_chains(opts) != 0)
    {
        log_msg(LOG_WARNING,
                "fw_initialize() Warning: Errors detected during fwknop custom chain creation");
        res = 0;
    }

    /* Make sure that the 'comment' match is available
    */
    if(strncasecmp(opts->config[CONF_ENABLE_IPT_COMMENT_CHECK], "Y", 1) == 0)
    {
        if(comment_match_exists(opts) == 1)
        {
            log_msg(LOG_INFO, "iptables 'comment' match is available");
        }
        else
        {
            log_msg(LOG_WARNING, "Warning: Could not use the 'comment' match");
            res = 0;
        }
    }

    return(res);
}

int
fw_cleanup(const fko_srv_options_t * const opts)
{
    if(strncasecmp(opts->config[CONF_FLUSH_IPT_AT_EXIT], "N", 1) == 0
            && opts->fw_flush == 0)
        return(0);

    delete_all_chains(opts);
    return(0);
}

static int
create_rule(const fko_srv_options_t * const opts,
        const char * const fw_chain, const char * const fw_rule)
{
    int res = 0;

    zero_cmd_buffers();

    if (strncasecmp(opts->config[CONF_ENABLE_RULE_PREPEND], "Y", 1) == 0) {
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s -I %s %s",
                opts->fw_config->fw_command, fw_chain, fw_rule);
    } else {
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s -A %s %s",
                opts->fw_config->fw_command, fw_chain, fw_rule);
    }
    res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE, WANT_STDERR,
                NO_TIMEOUT, &pid_status, opts);
    chop_newline(err_buf);

    log_msg(LOG_DEBUG, "create_rule() CMD: '%s' (res: %d, err: %s)",
        cmd_buf, res, err_buf);

    if(EXTCMD_IS_SUCCESS(res))
    {
        log_msg(LOG_DEBUG, "create_rule() Rule: '%s' added to %s",
                fw_rule, fw_chain);
        res = 1;
    }
    else
        log_msg(LOG_ERR, "create_rule() Error %i from cmd:'%s': %s",
                res, cmd_buf, err_buf);

    return res;
}

static void
ipt_rule(const fko_srv_options_t * const opts,
        const char * const complete_rule_buf,
        const char * const fw_rule_macro,
        const char * const srcip,
        const char * const dstip,
        const unsigned int proto,
        const unsigned int port,
        const char * const nat_ip,
        const unsigned int nat_port,
        struct fw_chain * const chain,
        const unsigned int exp_ts,
        const time_t now,
        const char * const msg,
        const char * const access_msg)
{
    char rule_buf[CMD_BUFSIZE] = {0};

    if(complete_rule_buf != NULL && complete_rule_buf[0] != 0x0)
    {
        strlcpy(rule_buf, complete_rule_buf, CMD_BUFSIZE-1);
    }
    else
    {
        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, fw_rule_macro,
            chain->table,
            proto,
            srcip,
            dstip,
            port,
            exp_ts,
            chain->target
        );
    }

    /* Check to make sure that the chain and jump rule exist
    */
    mk_chain(opts, chain->type);

    if(rule_exists(opts, chain, rule_buf, proto, srcip,
                dstip, port, nat_ip, nat_port, exp_ts) == 0)
    {
        if(create_rule(opts, chain->to_chain, rule_buf))
        {
            log_msg(LOG_INFO, "Added %s rule to %s for %s -> %s %s, expires at %u",
                msg, chain->to_chain, srcip, (dstip == NULL) ? IPT_ANY_IP : dstip,
                access_msg, exp_ts
            );

            chain->active_rules++;

            /* Reset the next expected expire time for this chain if it
            * is warranted.
            */
            if(chain->next_expire < now || exp_ts < chain->next_expire)
                chain->next_expire = exp_ts;
        }
    }

    return;
}

static void forward_access_rule(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc,
        struct fw_chain * const fwd_chain,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int fst_proto,
        const unsigned int fst_port,
        spa_data_t * const spadat,
        const unsigned int exp_ts,
        const time_t now)
{
    char   rule_buf[CMD_BUFSIZE] = {0};

    log_msg(LOG_DEBUG,
            "forward_access_rule() forward_all: %d, nat_ip: %s, nat_port: %d",
            acc->forward_all, nat_ip, nat_port);

    memset(rule_buf, 0, CMD_BUFSIZE);
    if(acc->forward_all)
    {

        snprintf(rule_buf, CMD_BUFSIZE-1, IPT_FWD_ALL_RULE_ARGS,
            fwd_chain->table,
            spadat->use_src_ip,
            exp_ts,
            fwd_chain->target
        );

        /* Make a global ACCEPT rule for all ports/protocols
        */
        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
            fwd_chain, exp_ts, now, "FORWARD ALL", "*/*");
    }
    else
    {
        snprintf(rule_buf, CMD_BUFSIZE-1, IPT_FWD_RULE_ARGS,
            fwd_chain->table,
            fst_proto,
            spadat->use_src_ip,
            nat_port,
            exp_ts,
            fwd_chain->target
        );
        /* Make the FORWARD access rule
        */
        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, fst_proto, nat_port, NULL, NAT_ANY_PORT,
            fwd_chain, exp_ts, now, "FORWARD", spadat->spa_message_remain);
    }
    return;
}

static void dnat_rule(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc,
        struct fw_chain * const dnat_chain,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int fst_proto,
        const unsigned int fst_port,
        spa_data_t * const spadat,
        const unsigned int exp_ts,
        const time_t now)
{
    char   rule_buf[CMD_BUFSIZE] = {0};

    log_msg(LOG_DEBUG, "dnat_rule() forward_all: %d, nat_ip: %s, nat_port: %d",
            acc->forward_all, nat_ip, nat_port);

    if(acc->forward_all)
    {
        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, IPT_DNAT_ALL_RULE_ARGS,
            dnat_chain->table,
            spadat->use_src_ip,
            (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
            exp_ts,
            dnat_chain->target,
            nat_ip
        );

        /* Make a global DNAT rule for all ports/protocols
        */
        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
            dnat_chain, exp_ts, now, "DNAT ALL", "*/*");
    }
    else
    {
        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, IPT_DNAT_RULE_ARGS,
            dnat_chain->table,
            fst_proto,
            spadat->use_src_ip,
            (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
            fst_port,
            exp_ts,
            dnat_chain->target,
            nat_ip,
            nat_port
        );

        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
            fst_proto, fst_port, nat_ip, nat_port, dnat_chain, exp_ts, now,
            "DNAT", spadat->spa_message_remain);
    }
    return;
}

static void snat_rule(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc,
        const char * const nat_ip,
        const unsigned int nat_port,
        const unsigned int fst_proto,
        const unsigned int fst_port,
        spa_data_t * const spadat,
        const unsigned int exp_ts,
        const time_t now)
{
    char     rule_buf[CMD_BUFSIZE] = {0};
    char     snat_target[SNAT_TARGET_BUFSIZE] = {0};
    struct   fw_chain *snat_chain = NULL;

    log_msg(LOG_DEBUG,
            "snat_rule() forward_all: %d, nat_ip: %s, nat_port: %d, force_snat: %d, force_snat_ip: %s, force_masq: %d",
            acc->forward_all, nat_ip, nat_port, acc->force_snat,
            (acc->force_snat_ip == NULL) ? "(NONE)" : acc->force_snat_ip,
            acc->force_masquerade);

    if(acc->forward_all)
    {
        /* Default to MASQUERADE */
        snat_chain = &(opts->fw_config->chain[IPT_MASQUERADE_ACCESS]);
        snprintf(snat_target, SNAT_TARGET_BUFSIZE-1, " ");

        /* Add SNAT or MASQUERADE rules.
        */
        if(acc->force_snat && acc->force_snat_ip != NULL && is_valid_ipv4_addr(acc->force_snat_ip, strlen(acc->force_snat_ip)))
        {
            /* Using static SNAT */
            snat_chain = &(opts->fw_config->chain[IPT_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s", acc->force_snat_ip);
        }
        else if((opts->config[CONF_SNAT_TRANSLATE_IP] != NULL)
            && is_valid_ipv4_addr(opts->config[CONF_SNAT_TRANSLATE_IP], strlen(opts->config[CONF_SNAT_TRANSLATE_IP])))
        {
            /* Using static SNAT */
            snat_chain = &(opts->fw_config->chain[IPT_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s", opts->config[CONF_SNAT_TRANSLATE_IP]);
        }

        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, IPT_SNAT_ALL_RULE_ARGS,
            snat_chain->table,
            spadat->use_src_ip,
            exp_ts,
            snat_chain->target,
            snat_target
        );

        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
            NULL, ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
            snat_chain, exp_ts, now, "SNAT ALL", "*/*");
    }
    else
    {
        /* Add SNAT or MASQUERADE rules.
        */
        if(acc->force_snat && acc->force_snat_ip != NULL && is_valid_ipv4_addr(acc->force_snat_ip, strlen(acc->force_snat_ip)))
        {
            /* Using static SNAT */
            snat_chain = &(opts->fw_config->chain[IPT_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s", acc->force_snat_ip);
        }
        else if(acc->force_snat && acc->force_masquerade)
        {
            /* Using MASQUERADE */
            snat_chain = &(opts->fw_config->chain[IPT_MASQUERADE_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-ports %i", fst_port);
        }
        else if((opts->config[CONF_SNAT_TRANSLATE_IP] != NULL)
            && is_valid_ipv4_addr(opts->config[CONF_SNAT_TRANSLATE_IP], strlen(opts->config[CONF_SNAT_TRANSLATE_IP])))
        {
            /* Using static SNAT */
            snat_chain = &(opts->fw_config->chain[IPT_SNAT_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-source %s", opts->config[CONF_SNAT_TRANSLATE_IP]);
        }
        else
        {
            /* Using MASQUERADE */
            snat_chain = &(opts->fw_config->chain[IPT_MASQUERADE_ACCESS]);
            snprintf(snat_target, SNAT_TARGET_BUFSIZE-1,
                "--to-ports %i", fst_port);
        }

        memset(rule_buf, 0, CMD_BUFSIZE);

        snprintf(rule_buf, CMD_BUFSIZE-1, IPT_SNAT_RULE_ARGS,
            snat_chain->table,
            fst_proto,
            nat_ip,
            nat_port,
            exp_ts,
            snat_chain->target,
            snat_target
        );

        ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
                NULL, fst_proto, nat_port, nat_ip, nat_port,
                snat_chain, exp_ts, now, "SNAT",
                spadat->spa_message_remain);
    }
    return;
}

/****************************************************************************/

/* Rule Processing - Create an access request...
*/
int
process_spa_request(const fko_srv_options_t * const opts,
        const acc_stanza_t * const acc, spa_data_t * const spadat)
{
    char            rule_buf[CMD_BUFSIZE] = {0};
    char            nat_ip[MAX_IPV4_STR_LEN] = {0};
    char            nat_dst[MAX_HOSTNAME_LEN] = {0};

    unsigned int    nat_port = 0;
    unsigned int    fst_proto = ANY_PROTO;
    unsigned int    fst_port = ANY_PORT;

    struct fw_chain * const in_chain   = &(opts->fw_config->chain[IPT_INPUT_ACCESS]);
    struct fw_chain * const out_chain  = &(opts->fw_config->chain[IPT_OUTPUT_ACCESS]);
    struct fw_chain * const fwd_chain  = &(opts->fw_config->chain[IPT_FORWARD_ACCESS]);
    struct fw_chain * const dnat_chain = &(opts->fw_config->chain[IPT_DNAT_ACCESS]);

    acc_port_list_t *port_list = NULL;
    acc_port_list_t *ple = NULL;

    char            *ndx = NULL;
    int             res = 0, is_err;
    int             access_any = strcmp(spadat->spa_message_remain, "ANY") == 0;
    int             str_len;
    time_t          now;
    unsigned int    exp_ts;

    if(access_any && (acc->force_nat
            || spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
            || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG
            || spadat->message_type == FKO_NAT_ACCESS_MSG
            || spadat->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG))
        return res;

    /* Parse and expand our access message.
    */
    if(!access_any
            && expand_acc_port_list(&port_list, spadat->spa_message_remain) != 1)
    {
        /* technically we would already have exited with an error if there were
         * any memory allocation errors (see the add_port_list() function), but
         * for completeness...
        */
        free_acc_port_list(port_list);
        return res;
    }

    /* Start at the top of the proto-port list...
    */
    ple = port_list;

    /* Remember the first proto/port combo in case we need them
     * for NAT access requests.
    */
    if(!access_any)
    {
        fst_proto = ple->proto;
        fst_port  = ple->port;
    }

    /* Set our expire time value.
    */
    time(&now);
    exp_ts = now + spadat->fw_access_timeout;

    /* deal with SPA packets that themselves request a NAT operation
    */
    if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG
      || spadat->message_type == FKO_NAT_ACCESS_MSG
      || spadat->message_type == FKO_CLIENT_TIMEOUT_NAT_ACCESS_MSG
      || acc->force_nat)
    {
        if(acc->force_nat)
        {
            strlcpy(nat_ip, acc->force_nat_ip, sizeof(nat_ip));
            nat_port = acc->force_nat_port;
        }
        else
        {
            ndx = strchr(spadat->nat_access, ',');
            str_len = strcspn(spadat->nat_access, ",");
            if((ndx != NULL) && (str_len <= MAX_HOSTNAME_LEN))
            {
                strlcpy(nat_dst, spadat->nat_access, str_len+1);
                if(! is_valid_ipv4_addr(nat_dst, str_len))
                {
                    if(strncasecmp(opts->config[CONF_ENABLE_NAT_DNS], "Y", 1) == 0)
                    {
                        if (!is_valid_hostname(nat_dst, str_len))
                        {
                            log_msg(LOG_INFO, "Invalid Hostname in NAT SPA message");
                            free_acc_port_list(port_list);
                            return res;
                        }
                        if (ipv4_resolve(nat_dst, nat_ip) == 0)
                        {
                            log_msg(LOG_INFO, "Resolved NAT IP in SPA message");
                        }
                        else
                        {
                            log_msg(LOG_INFO, "Unable to resolve Hostname in NAT SPA message");
                            free_acc_port_list(port_list);
                            return res;
                        }
                    }
                    else
                    {
                        log_msg(LOG_INFO, "Received Hostname in NAT SPA message, but hostname is disabled.");
                        free_acc_port_list(port_list);
                        return res;

                    }
                }
                else
                {
                    strlcpy(nat_ip, nat_dst, MAX_IPV4_STR_LEN);
                }

                nat_port = strtol_wrapper(ndx+1, 0, MAX_PORT,
                        NO_EXIT_UPON_ERR, &is_err);
                if(is_err != FKO_SUCCESS)
                {
                    log_msg(LOG_INFO, "Invalid NAT port in SPA message");
                    free_acc_port_list(port_list);
                    res = is_err;
                    return res;
                }
            }
            else
            {
                log_msg(LOG_INFO, "Invalid NAT IP in SPA message");
                free_acc_port_list(port_list);
                return res;
            }
        }

        if(spadat->message_type == FKO_LOCAL_NAT_ACCESS_MSG
                || spadat->message_type == FKO_CLIENT_TIMEOUT_LOCAL_NAT_ACCESS_MSG)
        {
            ipt_rule(opts, NULL, IPT_RULE_ARGS, spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
                fst_proto, nat_port, nat_ip, nat_port, in_chain, exp_ts,
                now, "local NAT", spadat->spa_message_remain);
        }
        else if(strlen(fwd_chain->to_chain))
        {
            /* FORWARD access rule
            */
            forward_access_rule(opts, acc, fwd_chain, nat_ip,
                    nat_port, fst_proto, fst_port, spadat, exp_ts, now);
        }

        /* DNAT rule
        */
        if(strlen(dnat_chain->to_chain) && !acc->disable_dnat)
            dnat_rule(opts, acc, dnat_chain, nat_ip,
                    nat_port, fst_proto, fst_port, spadat, exp_ts, now);

        /* SNAT rule
        */
        if(acc->force_snat || strncasecmp(opts->config[CONF_ENABLE_IPT_SNAT], "Y", 1) == 0)
            snat_rule(opts, acc, nat_ip, nat_port,
                    fst_proto, fst_port, spadat, exp_ts, now);
    }
    else /* Non-NAT request - this is the typical case. */
    {
        if(access_any)
        {
            snprintf(rule_buf, CMD_BUFSIZE-1, IPT_ANY_ACCESS_RULE_ARGS,
                in_chain->table,
                spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
                exp_ts,
                in_chain->target
            );
            ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
                ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
                in_chain, exp_ts, now, "access", spadat->spa_message_remain);

            if(strlen(out_chain->to_chain))
            {
                snprintf(rule_buf, CMD_BUFSIZE-1, IPT_OUT_ANY_ACCESS_RULE_ARGS,
                    out_chain->table,
                    spadat->use_src_ip,
                    (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
                    exp_ts,
                    out_chain->target
                );
                ipt_rule(opts, rule_buf, NULL, spadat->use_src_ip,
                    (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
                    ANY_PROTO, ANY_PORT, NULL, NAT_ANY_PORT,
                    out_chain, exp_ts, now, "OUTPUT", spadat->spa_message_remain);
            }
        }

        /* Create an access command for each proto/port for the source ip.
        */
        while(ple != NULL)
        {
            ipt_rule(opts, NULL, IPT_RULE_ARGS, spadat->use_src_ip,
                (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
                ple->proto, ple->port, NULL, NAT_ANY_PORT,
                in_chain, exp_ts, now, "access", spadat->spa_message_remain);

            /* We need to make a corresponding OUTPUT rule if out_chain target
             * is not NULL.
            */
            if(strlen(out_chain->to_chain))
            {
                ipt_rule(opts, NULL, IPT_OUT_RULE_ARGS, spadat->use_src_ip,
                    (fwc.use_destination ? spadat->pkt_destination_ip : IPT_ANY_IP),
                    ple->proto, ple->port, NULL, NAT_ANY_PORT,
                    out_chain, exp_ts, now, "OUTPUT", spadat->spa_message_remain);
            }
            ple = ple->next;
        }
    }

    /* Done with the port list for access rules.
    */
    free_acc_port_list(port_list);

    return(res);
}

static void
rm_expired_rules(const fko_srv_options_t * const opts,
        const char * const ipt_output_buf,
        char *ndx, struct fw_chain *ch, int cpos, time_t now)
{
    char        exp_str[12]     = {0};
    char        rule_num_str[6] = {0};
    char        *rn_start, *rn_end, *tmp_mark;

    int         res, is_err, rn_offset=0, rule_num;
    time_t      rule_exp, min_exp = 0;

    /* walk the list and process rules as needed.
    */
    while (ndx != NULL) {
        /* Jump forward and extract the timestamp
        */
        ndx += strlen(EXPIRE_COMMENT_PREFIX);

        /* remember this spot for when we look for the next
         * rule.
        */
        tmp_mark = ndx;

        strlcpy(exp_str, ndx, sizeof(exp_str));
        if (strchr(exp_str, '*') != NULL)
            strchr(exp_str, '*')[0] = '\0';

        chop_spaces(exp_str);
        if(!is_digits(exp_str))
        {
            /* go to the next rule if it exists
            */
            ndx = strstr(tmp_mark, EXPIRE_COMMENT_PREFIX);
            continue;
        }

        rule_exp = (time_t)atoll(exp_str);

        if(rule_exp <= now)
        {
            /* Backtrack and get the rule number and delete it.
            */
            rn_start = ndx;
            while(--rn_start > ipt_output_buf)
            {
                if(*rn_start == '\n')
                    break;
            }

            if(*rn_start != '\n')
            {
                /* This should not happen. But if it does, complain,
                 * decrement the active rule value, and go on.
                */
                log_msg(LOG_ERR,
                    "Rule parse error while finding rule line start in chain %i",
                    cpos);

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;

                break;
            }
            rn_start++;

            rn_end = strchr(rn_start, ' ');
            if(rn_end == NULL)
            {
                /* This should not happen. But if it does, complain,
                 * decrement the active rule value, and go on.
                */
                log_msg(LOG_ERR,
                    "Rule parse error while finding rule number in chain %i",
                    cpos);

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;

                break;
            }

            strlcpy(rule_num_str, rn_start, (rn_end - rn_start)+1);

            rule_num = strtol_wrapper(rule_num_str, rn_offset, RCHK_MAX_IPT_RULE_NUM,
                    NO_EXIT_UPON_ERR, &is_err);
            if(is_err != FKO_SUCCESS)
            {
                log_msg(LOG_ERR,
                    "Rule parse error while finding rule number in chain %i",
                    cpos);

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;

                break;
            }

            zero_cmd_buffers();

            snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_DEL_RULE_ARGS,
                opts->fw_config->fw_command,
                ch[cpos].table,
                ch[cpos].to_chain,
                rule_num - rn_offset /* account for position of previously
                                        deleted rule with rn_offset */
            );

            res = run_extcmd(cmd_buf, err_buf, CMD_BUFSIZE,
                    WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
            chop_newline(err_buf);

            log_msg(LOG_DEBUG, "rm_expired_rules() CMD: '%s' (res: %d, err: %s)",
                cmd_buf, res, err_buf);

            if(EXTCMD_IS_SUCCESS(res))
            {
                log_msg(LOG_INFO, "Removed rule %s from %s with expire time of %u",
                    rule_num_str, ch[cpos].to_chain, rule_exp
                );

                rn_offset++;

                if (ch[cpos].active_rules > 0)
                    ch[cpos].active_rules--;
            }
            else
                log_msg(LOG_ERR, "rm_expired_rules() Error %i from cmd:'%s': %s",
                        res, cmd_buf, err_buf);

        }
        else
        {
            /* Track the minimum future rule expire time.
            */
            min_exp = (min_exp < rule_exp) ? min_exp : rule_exp;
        }

        /* Push our tracking index forward beyond (just processed) _exp_
         * string so we can continue to the next rule in the list.
        */
        ndx = strstr(tmp_mark, EXPIRE_COMMENT_PREFIX);
    }

    /* Set the next pending expire time accordingly. 0 if there are no
     * more rules, or whatever the next expected (min_exp) time will be.
    */
    if(ch[cpos].active_rules < 1)
        ch[cpos].next_expire = 0;
    else if(min_exp)
        ch[cpos].next_expire = min_exp;

    return;
}

/* Iterate over the configure firewall access chains and purge expired
 * firewall rules.
*/
void
check_firewall_rules(const fko_srv_options_t * const opts,
        const int chk_rm_all)
{
    char            *ndx;
    char            ipt_output_buf[STANDARD_CMD_OUT_BUFSIZE] = {0};

    int             i, res;
    time_t          now;

    struct fw_chain *ch = opts->fw_config->chain;

    time(&now);

    /* Iterate over each chain and look for active rules to delete.
    */
    for(i=0; i < NUM_FWKNOP_ACCESS_TYPES; i++)
    {
        /* If there are no active rules or we have not yet
         * reached our expected next expire time, continue.
        */
        if(!chk_rm_all && (ch[i].active_rules == 0 || ch[i].next_expire > now))
            continue;

        if(ch[i].table[0] == '\0' || ch[i].to_chain[i] == '\0')
            continue;

        zero_cmd_buffers();
        memset(ipt_output_buf, 0x0, STANDARD_CMD_OUT_BUFSIZE);

        /* Get the current list of rules for this chain and delete
         * any that have expired. Note that chk_rm_all puts us in
         * garbage collection mode, and allows any rules that have
         * been manually added (potentially by a program separate
         * from fwknopd) to take advantage of fwknopd's timeout
         * mechanism.
        */
        snprintf(cmd_buf, CMD_BUFSIZE-1, "%s " IPT_LIST_RULES_ARGS,
            opts->fw_config->fw_command,
            ch[i].table,
            ch[i].to_chain
        );

        res = run_extcmd(cmd_buf, ipt_output_buf, STANDARD_CMD_OUT_BUFSIZE,
                WANT_STDERR, NO_TIMEOUT, &pid_status, opts);
        chop_newline(ipt_output_buf);

        log_msg(LOG_DEBUG,
            "check_firewall_rules() CMD: '%s' (res: %d, ipt_output_buf: %s)",
            cmd_buf, res, ipt_output_buf);

        if(!EXTCMD_IS_SUCCESS(res))
        {
            log_msg(LOG_ERR,
                    "check_firewall_rules() Error %i from cmd:'%s': %s",
                    res, cmd_buf, ipt_output_buf);
            continue;
        }

        log_msg(LOG_DEBUG, "RES=%i, CMD_BUF: %s\nRULES LIST: %s",
                res, cmd_buf, ipt_output_buf);

        ndx = strstr(ipt_output_buf, EXPIRE_COMMENT_PREFIX);
        if(ndx == NULL)
        {
            /* we did not find a candidate rule to expire
            */
            log_msg(LOG_DEBUG,
                "Did not find expire comment in rules list %i", i);

            if (ch[i].active_rules > 0)
                ch[i].active_rules--;

            continue;
        }

        rm_expired_rules(opts, ipt_output_buf, ndx, ch, i, now);
    }

    return;
}

int
validate_ipt_chain_conf(const char * const chain_str)
{
    int         j, rv  = 1;
    const char   *ndx  = chain_str;

    j = 1;
    while(*ndx != '\0')
    {
        if(*ndx == ',')
            j++;

        if(*ndx != '\0'
                && *ndx != ' '
                && *ndx != ','
                && *ndx != '_'
                && isalnum(*ndx) == 0)
        {
            rv = 0;
            break;
        }
        ndx++;
    }

    /* Sanity check - j should be the number of chain fields
     * (excluding the type).
    */
    if(j != FW_NUM_CHAIN_FIELDS)
        rv = 0;

    return rv;
}

#define MAX_CMD_LEN 256
#define MAX_PORTS 20
#define MAX_RULE_LINE 4096
#define TEMP_RULES_FILE "/tmp/iptables_temp.rules"
#define BACKUP_RULES_FILE "/tmp/iptables_backup.rules"

typedef struct input_rule_list {
    char *rule;
    struct input_rule_list *next;
} input_rule_list_t;

static void free_rule_list(input_rule_list_t *rules) {
    input_rule_list_t *next;

    while (rules != NULL) {
        next = rules->next;
        free(rules->rule);
        free(rules);
        rules = next;
    }
}

static int append_rule(input_rule_list_t **head, input_rule_list_t **tail,
        const char *rule) {
    input_rule_list_t *node = calloc(1, sizeof(*node));

    if (node == NULL)
        return -1;

    node->rule = strdup(rule);
    if (node->rule == NULL) {
        free(node);
        return -1;
    }

    if (*tail != NULL)
        (*tail)->next = node;
    else
        *head = node;

    *tail = node;
    return 0;
}

static int rule_list_contains_exact(const input_rule_list_t *rules,
        const char *rule) {
    while (rules != NULL) {
        if (strcmp(rules->rule, rule) == 0)
            return 1;
        rules = rules->next;
    }

    return 0;
}

static int append_unique_rule(input_rule_list_t **head, input_rule_list_t **tail,
        const char *rule) {
    if (rule_list_contains_exact(*head, rule))
        return 0;

    return append_rule(head, tail, rule);
}

static int line_contains_token(const char *line, const char *token) {
    const char *ndx = line;
    const size_t token_len = strlen(token);

    while ((ndx = strstr(ndx, token)) != NULL) {
        const int before_ok = (ndx == line)
            || isspace((unsigned char) *(ndx - 1));
        const char after = *(ndx + token_len);
        const int after_ok = after == '\0'
            || isspace((unsigned char) after)
            || after == ',';

        if (before_ok && after_ok)
            return 1;

        ndx++;
    }

    return 0;
}

static int rule_list_contains_port_accept(const input_rule_list_t *rules,
        const char *proto, const char *port) {
    char proto_token[16];
    char port_token[32];

    snprintf(proto_token, sizeof(proto_token), "-p %s", proto);
    snprintf(port_token, sizeof(port_token), "--dport %s", port);

    while (rules != NULL) {
        if (strncmp(rules->rule, "-A INPUT ", 9) == 0
                && line_contains_token(rules->rule, proto_token)
                && line_contains_token(rules->rule, port_token)
                && line_contains_token(rules->rule, "-j ACCEPT"))
            return 1;

        rules = rules->next;
    }

    return 0;
}

static int chain_definition_matches(const char *line, const char *chain) {
    size_t chain_len;

    if (chain == NULL || chain[0] == '\0' || line[0] != ':')
        return 0;

    chain_len = strlen(chain);

    return strncmp(line + 1, chain, chain_len) == 0
        && line[chain_len + 1] == ' ';
}

static int valid_port_string(const char *port) {
    char *endptr = NULL;
    long port_num;

    if (port == NULL || port[0] == '\0')
        return 0;

    port_num = strtol(port, &endptr, 10);
    return *endptr == '\0' && port_num >= 1 && port_num <= 65535;
}

static int port_entry_exists(char ports[MAX_PORTS][16],
        char protocols[MAX_PORTS][4],
        int port_count,
        const char *proto,
        const char *port) {
    int i;

    for (i = 0; i < port_count; i++) {
        if (strcmp(protocols[i], proto) == 0 && strcmp(ports[i], port) == 0)
            return 1;
    }

    return 0;
}

static int add_port_entry(char ports[MAX_PORTS][16],
        char protocols[MAX_PORTS][4],
        int *port_count,
        const char *proto,
        const char *port) {
    if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0)
        return -1;

    if (!valid_port_string(port))
        return -1;

    if (port_entry_exists(ports, protocols, *port_count, proto, port))
        return 0;

    if (*port_count >= MAX_PORTS)
        return -1;

    snprintf(protocols[*port_count], 4, "%s", proto);
    snprintf(ports[*port_count], 16, "%s", port);
    (*port_count)++;
    return 1;
}

static int detect_ssh_connection_port(char *port, size_t port_len) {
    const char *value = getenv("SSH_CONNECTION");
    char client_ip[128];
    char client_port[16];
    char server_ip[128];
    char server_port[16];

    if (value == NULL || value[0] == '\0')
        return 0;

    if (sscanf(value, "%127s %15s %127s %15s",
                client_ip, client_port, server_ip, server_port) != 4)
        return 0;

    if (!valid_port_string(server_port))
        return 0;

    snprintf(port, port_len, "%s", server_port);
    return 1;
}

static int detect_ssh_client_port(char *port, size_t port_len) {
    const char *value = getenv("SSH_CLIENT");
    char client_ip[128];
    char client_port[16];
    char server_port[16];

    if (value == NULL || value[0] == '\0')
        return 0;

    if (sscanf(value, "%127s %15s %15s",
                client_ip, client_port, server_port) != 3)
        return 0;

    if (!valid_port_string(server_port))
        return 0;

    snprintf(port, port_len, "%s", server_port);
    return 1;
}

static int add_ssh_fallback_ports(char ports[MAX_PORTS][16],
        char protocols[MAX_PORTS][4],
        int *port_count) {
    char detected_port[16];
    int rv;

    rv = add_port_entry(ports, protocols, port_count, "tcp", "22");
    if (rv < 0) {
        printf("Failed to keep SSH fallback port tcp/22 open.\n");
        return -1;
    }
    if (rv > 0)
        printf("The SSH fallback port tcp/22 will be kept open to avoid lockout.\n");

    if (detect_ssh_connection_port(detected_port, sizeof(detected_port))
            || detect_ssh_client_port(detected_port, sizeof(detected_port))) {
        if (strcmp(detected_port, "22") == 0)
            return 0;

        rv = add_port_entry(ports, protocols, port_count, "tcp", detected_port);
        if (rv < 0) {
            printf("Failed to keep detected SSH port tcp/%s open.\n", detected_port);
            return -1;
        }
        if (rv > 0)
            printf("Detected current SSH server port tcp/%s; it will be kept open.\n",
                    detected_port);
    }

    return 0;
}

static void strip_line_end(char *line) {
    line[strcspn(line, "\r\n")] = '\0';
}

static int line_was_truncated(const char *line, FILE *fp) {
    const size_t len = strlen(line);

    return len > 0 && line[len - 1] != '\n' && !feof(fp);
}

static int emit_rebuilt_input_rules(FILE *temp_rules,
        char ports[MAX_PORTS][16],
        char protocols[MAX_PORTS][4],
        int port_count,
        const char *fwknop_input_chain,
        int add_fwknop_input_jump) {
    input_rule_list_t *merged_rules = NULL;
    input_rule_list_t *merged_tail = NULL;
    input_rule_list_t *rule = NULL;
    char port_rule[128];
    int i;
    int rv = -1;

    if (append_unique_rule(&merged_rules, &merged_tail,
                "-A INPUT -i lo -j ACCEPT") != 0)
        goto cleanup;
    if (append_unique_rule(&merged_rules, &merged_tail,
                "-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT") != 0)
        goto cleanup;
    if (append_unique_rule(&merged_rules, &merged_tail,
                "-A INPUT -p icmp -j ACCEPT") != 0)
        goto cleanup;

    for (i = 0; i < port_count; i++) {
        if (rule_list_contains_port_accept(merged_rules, protocols[i], ports[i]))
            continue;

        snprintf(port_rule, sizeof(port_rule),
                "-A INPUT -p %s --dport %s -j ACCEPT",
                protocols[i], ports[i]);

        if (append_unique_rule(&merged_rules, &merged_tail, port_rule) != 0)
            goto cleanup;
    }

    if (add_fwknop_input_jump && fwknop_input_chain != NULL
            && fwknop_input_chain[0] != '\0') {
        snprintf(port_rule, sizeof(port_rule),
                "-A INPUT -j %s", fwknop_input_chain);

        if (append_unique_rule(&merged_rules, &merged_tail, port_rule) != 0)
            goto cleanup;
    }

    for (rule = merged_rules; rule != NULL; rule = rule->next)
        fprintf(temp_rules, "%s\n", rule->rule);

    rv = 0;

cleanup:
    free_rule_list(merged_rules);
    return rv;
}

static int build_input_only_rules_file(const char *source_path,
        const char *dest_path,
        char ports[MAX_PORTS][16],
        char protocols[MAX_PORTS][4],
        int port_count,
        const char *fwknop_input_chain) {
    FILE *current_rules = NULL;
    FILE *temp_rules = NULL;
    char line[MAX_RULE_LINE];
    int in_filter = 0;
    int saw_filter = 0;
    int saw_input_chain = 0;
    int saw_fwknop_input_chain = 0;
    int rv = -1;

    current_rules = fopen(source_path, "r");
    if (current_rules == NULL) {
        perror("Failed to read current iptables rules");
        return -1;
    }

    temp_rules = fopen(dest_path, "w");
    if (temp_rules == NULL) {
        perror("Failed to create temporary rules file");
        fclose(current_rules);
        return -1;
    }

    while (fgets(line, sizeof(line), current_rules) != NULL) {
        if (line_was_truncated(line, current_rules)) {
            printf("iptables-save output contains a rule longer than %d bytes.\n",
                    MAX_RULE_LINE - 1);
            goto cleanup;
        }

        strip_line_end(line);

        if (strcmp(line, "*filter") == 0) {
            in_filter = 1;
            saw_filter = 1;
            saw_input_chain = 0;
            fprintf(temp_rules, "%s\n", line);
            continue;
        }

        if (in_filter && strcmp(line, "COMMIT") == 0) {
            if (!saw_input_chain)
                fprintf(temp_rules, ":INPUT DROP [0:0]\n");

            if (emit_rebuilt_input_rules(temp_rules,
                        ports, protocols, port_count, fwknop_input_chain,
                        saw_fwknop_input_chain) != 0) {
                printf("Failed to rebuild INPUT chain rules.\n");
                goto cleanup;
            }

            fprintf(temp_rules, "COMMIT\n");
            in_filter = 0;
            continue;
        }

        if (in_filter && strncmp(line, ":INPUT ", 7) == 0) {
            saw_input_chain = 1;
            fprintf(temp_rules, ":INPUT DROP [0:0]\n");
            continue;
        }

        if (in_filter && chain_definition_matches(line, fwknop_input_chain))
            saw_fwknop_input_chain = 1;

        if (in_filter && strncmp(line, "-A INPUT ", 9) == 0) {
            continue;
        }

        fprintf(temp_rules, "%s\n", line);
    }

    if (ferror(current_rules)) {
        perror("Failed while reading current iptables rules");
        goto cleanup;
    }

    if (in_filter) {
        printf("Invalid iptables-save output: missing COMMIT for filter table.\n");
        goto cleanup;
    }

    if (!saw_filter) {
        fprintf(temp_rules, "*filter\n");
        fprintf(temp_rules, ":INPUT DROP [0:0]\n");
        if (emit_rebuilt_input_rules(temp_rules,
                    ports, protocols, port_count, fwknop_input_chain, 0) != 0) {
            printf("Failed to rebuild INPUT chain rules.\n");
            goto cleanup;
        }
        fprintf(temp_rules, "COMMIT\n");
    }

    rv = 0;

cleanup:
    fclose(current_rules);
    fclose(temp_rules);

    if (rv != 0)
        remove(dest_path);

    return rv;
}

int execute_cmd_status(const char *cmd) {
    printf("Executing: %s\n", cmd);
    int status = system(cmd);
    if (status != 0) {
        printf("Command failed with status %d\n", status);
    }
    return status;
}

void execute_cmd(const char *cmd) {
    (void) execute_cmd_status(cmd);
}

void list_rules() {
    printf("\nCurrent INPUT Chain Rules:\n");
    printf("=========================\n");
    execute_cmd("iptables -L INPUT -n --line-numbers");
}

void timeout_handler(int sig) {
    printf("\nOperation timed out! No changes were made.\n");
    exit(1);
}

int validate_rules_file(const char *filename) {
    printf("Validating rules file...\n");
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, MAX_CMD_LEN, "iptables-restore -n < %s", filename);
    return system(cmd) == 0;
}

static int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

static int command_exists(const char *cmd) {
    char check_cmd[MAX_CMD_LEN];
    snprintf(check_cmd, sizeof(check_cmd),
            "command -v %s >/dev/null 2>&1", cmd);
    return system(check_cmd) == 0;
}

static int save_rules_to_path(const char *dir, const char *path) {
    char cmd[MAX_CMD_LEN];

    snprintf(cmd, sizeof(cmd), "mkdir -p %s", dir);
    if (execute_cmd_status(cmd) != 0)
        return -1;

    snprintf(cmd, sizeof(cmd), "iptables-save > %s", path);
    return execute_cmd_status(cmd) == 0 ? 0 : -1;
}

static int save_runtime_persistent_rules(void) {
    int saved = -1;

    if (file_exists("/etc/debian_version") || file_exists("/etc/lsb-release")) {
        saved = save_rules_to_path("/etc/iptables", "/etc/iptables/rules.v4");
        if (saved == 0 && command_exists("netfilter-persistent"))
            execute_cmd("netfilter-persistent save");
        else if (saved == 0)
            printf("Note: install netfilter-persistent or iptables-persistent to restore rules after reboot.\n");
        return saved;
    }

    if (file_exists("/etc/redhat-release")) {
        return save_rules_to_path("/etc/sysconfig", "/etc/sysconfig/iptables");
    }

    if (file_exists("/etc/iptables")) {
        saved = save_rules_to_path("/etc/iptables", "/etc/iptables/rules.v4");
        if (saved == 0)
            return 0;
    }

    return save_rules_to_path("/etc/sysconfig", "/etc/sysconfig/iptables");
}

int initialize_firewall(fko_srv_options_t * const opts) {
    char ports[MAX_PORTS][16];
    char protocols[MAX_PORTS][4];
    char port_buf[16];
    const char *listener_proto;
    int port_count = 0;
    char choice;
    unsigned int enable_udp_server = 0; 
    unsigned short port;
    printf("\nFirewall Initialization\n");
    printf("======================\n");
    printf("This will update only the INPUT chain.\n");
    printf("Other chains and tables will be preserved.\n");
    printf("Existing INPUT rules will be replaced with PortGuard allow rules.\n");
    printf("Recommended: Have physical console access or\n");
    printf("a secondary SSH session open as backup.\n");
    printf("Continue? (y/n): ");
    
    scanf(" %c", &choice);
    if (choice != 'y' && choice != 'Y') {
        printf("Initialization canceled.\n");
        return 0;
    }
    if(opts->enable_udp_server ||
        strncasecmp(opts->config[CONF_ENABLE_UDP_SERVER], "Y", 1) == 0)
        {
            enable_udp_server = 1;
        }
    port = enable_udp_server ? opts->udpserv_port : opts->tcpserv_port;
    listener_proto = enable_udp_server ? "udp" : "tcp";
    snprintf(port_buf, sizeof(port_buf), "%u", port);
    if (add_port_entry(ports, protocols, &port_count, listener_proto, port_buf) < 0) {
        printf("Failed to add fwknop listener port to firewall rules.\n");
        return -1;
    }
    printf("\nThe %s port %d listened to by fwknop will be added to the firewall rules.\n",
            listener_proto, port);
    if (add_ssh_fallback_ports(ports, protocols, &port_count) != 0)
        return -1;
    // Configure ports to open
    printf("\nConfigure additional ports to open (y/n)? ");
    scanf(" %c", &choice);
    while(getchar() != '\n'); 
    if (choice == 'y' || choice == 'Y') {
        printf("\nEnter ports to open (protocol port, e.g., 'tcp 22' or 'udp 53')\n");
        printf("Enter 'done' when finished (up to %d total allow ports):\n", MAX_PORTS);
        
        while (port_count < MAX_PORTS) {
            char input[32];
            char proto[4];
            char allow_port[16];
            int add_rv;
            printf("Port %d (format 'proto port' or 'done'): ", port_count + 1);
            
            // Read entire line
            if (fgets(input, sizeof(input), stdin) == NULL) {
                break;  // Handle EOF or error
            }
            
            // Remove newline
            input[strcspn(input, "\n")] = '\0';
            
            // Check for done command
            if (strcmp(input, "done") == 0) {
                break;
            }
            
            // Parse protocol and port
            if (sscanf(input, "%3s %15s", proto, allow_port) != 2) {
                printf("Invalid format. Use 'tcp 22' or 'udp 53' format.\n");
                continue;
            }
            
            // Validate protocol
            if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0) {
                printf("Invalid protocol. Only 'tcp' or 'udp' allowed.\n");
                continue;
            }
            
            // Validate port number
            if (!valid_port_string(allow_port)) {
                printf("Invalid port number. Must be 1-65535.\n");
                continue;
            }
            
            add_rv = add_port_entry(ports, protocols, &port_count, proto, allow_port);
            if (add_rv < 0) {
                printf("Unable to add port rule. Maximum number of ports reached.\n");
                continue;
            }
            if (add_rv == 0)
                printf("Port rule already configured; skipping duplicate.\n");
        }
    }

    // Backup current rules and build a restore file that only changes INPUT.
    if (execute_cmd_status("iptables-save > " BACKUP_RULES_FILE) != 0) {
        printf("Failed to back up current firewall rules. Aborting.\n");
        return -1;
    }

    if (build_input_only_rules_file(BACKUP_RULES_FILE, TEMP_RULES_FILE,
                ports, protocols, port_count,
                opts->fw_config->chain[IPT_INPUT_ACCESS].to_chain) != 0) {
        printf("Failed to prepare rebuilt INPUT chain rules. Aborting.\n");
        return -1;
    }
    
    // Validate the rules before applying
    if (!validate_rules_file(TEMP_RULES_FILE)) {
        printf("Rule validation failed! Aborting.\n");
        remove(TEMP_RULES_FILE);
        return -1;
    }

    // Set timeout in case the restore hangs
    alarm(60); // 1 minute timeout
    signal(SIGALRM, timeout_handler);
    
    // Apply new rules
    char cmd[MAX_CMD_LEN];
    snprintf(cmd, MAX_CMD_LEN, "iptables-restore < %s", TEMP_RULES_FILE);
    int restore_status = system(cmd);
    alarm(0); // Cancel timeout
    
    if (restore_status != 0) {
        printf("Error applying new rules! (Status: %d)\n", restore_status);
        printf("No changes were made to the firewall rules.\n");
        remove(TEMP_RULES_FILE);
        return -1;
    }
    
    // Save to permanent configuration
    if (save_runtime_persistent_rules() != 0) {
        printf("Warning: failed to save persistent firewall rules.\n");
        printf("The active rules were applied, but they may not survive reboot.\n");
    }
    
    printf("\nFirewall INPUT chain initialized successfully.\n");
    list_rules();
    remove(TEMP_RULES_FILE);
    return 0;
}

void save_persistent_rules() {
    printf("Saving rules to persistent configuration...\n");
    if (save_runtime_persistent_rules() != 0) {
        printf("Warning: failed to save persistent firewall rules.\n");
        printf("The active rules were applied, but they may not survive reboot.\n");
    }
}
void add_port_rule() {
    char protocol[4];
    char port[16];
    char cmd[MAX_CMD_LEN];
    char check_cmd[MAX_CMD_LEN];
    FILE *fp;
    
    printf("\nAdd Port Rule\n");
    printf("=============\n");
    
    // Get protocol input with validation
    while (1) {
        printf("Protocol (tcp/udp): ");
        if (scanf("%3s", protocol) != 1) {
            printf("Invalid input.\n");
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }
        
        if (strcmp(protocol, "tcp") == 0 || strcmp(protocol, "udp") == 0) {
            break;
        }
        printf("Error: Only 'tcp' or 'udp' are allowed.\n");
    }
    
    // Get port input with validation
    while (1) {
        printf("Port number: ");
        if (scanf("%15s", port) != 1) {
            printf("Invalid input.\n");
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }
        
        char *endptr;
        long port_num = strtol(port, &endptr, 10);
        if (*endptr != '\0' || port_num < 1 || port_num > 65535) {
            printf("Error: Port must be 1-65535.\n");
            continue;
        }
        break;
    }
    
    // Check if the rule already exists
    snprintf(check_cmd, MAX_CMD_LEN, 
             "iptables -C INPUT -p %s --dport %s -j ACCEPT 2>/dev/null", 
             protocol, port);
    
    if (system(check_cmd) == 0) {
        printf("\nWarning: This rule already exists!\n");
        printf("Existing rule: iptables -A INPUT -p %s --dport %s -j ACCEPT\n", 
               protocol, port);
        
        printf("Add anyway? (y/n): ");
        char confirm_dup;
        scanf(" %c", &confirm_dup);
        while (getchar() != '\n'); // Clear input buffer
        
        if (confirm_dup != 'y' && confirm_dup != 'Y') {
            printf("Operation canceled.\n");
            return;
        }
    }
    
    // Generate and confirm the rule
    snprintf(cmd, MAX_CMD_LEN, "iptables -A INPUT -p %s --dport %s -j ACCEPT", 
             protocol, port);
    
    printf("\nRule to add: %s\n", cmd);
    printf("Confirm? (y/n): ");
    
    char confirm;
    scanf(" %c", &confirm);
    while (getchar() != '\n'); // Clear input buffer
    
    if (confirm == 'y' || confirm == 'Y') {
        execute_cmd(cmd);
        save_persistent_rules();
        printf("Rule added successfully.\n");
    } else {
        printf("Operation canceled.\n");
    }
}

void delete_rule() {
    int rule_num;
    char cmd[MAX_CMD_LEN];
    
    list_rules();
    
    printf("\nDelete Rule\n");
    printf("===========\n");
    printf("Enter rule number to delete: ");
    scanf("%d", &rule_num);
    
    snprintf(cmd, MAX_CMD_LEN, "iptables -D INPUT %d", rule_num);
    
    printf("\nCommand to execute: %s\n", cmd);
    printf("Confirm? (y/n): ");
    
    char confirm;
    scanf(" %c", &confirm);
    
    if (confirm == 'y' || confirm == 'Y') {
        execute_cmd(cmd);
        save_persistent_rules();
        printf("Rule deleted successfully.\n");
    } else {
        printf("Operation canceled.\n");
    }
}

void show_menu() {
    printf("\nFirewall Port Manager\n");
    printf("====================\n");
    printf("1. Initialize INPUT chain (preserve other chains)\n");
    printf("2. List current rules\n");
    printf("3. Add port rule\n");
    printf("4. Delete rule\n");
    printf("0. Exit\n");
    printf("====================\n");
    printf("Select option: ");
}

int firewall_cmds(fko_srv_options_t * const opts) {
    if (getuid() != 0) {
        printf("Error: Must be run as root\n");
        return 1;
    }

    int choice;
    do {
        show_menu();
        scanf("%d", &choice);
        
        switch(choice) {
            case 1:
                initialize_firewall(opts);
                break;
            case 2:
                list_rules();
                break;
            case 3:
                add_port_rule();
                break;
            case 4:
                delete_rule();
                break;
            case 0:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid option\n");
        }
    } while (choice != 0);
    
    return 0;
}

#endif /* FIREWALL_IPTABLES */

/***EOF***/
