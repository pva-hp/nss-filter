AC_INIT([nss-filter],[1.0],[pva-outdoor@yandex.ru],[nss-filter],[https://github.com/pva-outdoor/nss-filter.git])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AC_PROG_CC
LT_INIT

dnl TODO: configure blacklist file with WITH
dnl AC_WITH() 

AC_DEFINE([BLACKLIST_FILE], ["hosts.blacklist"], [Blacklist file name])
AC_DEFINE([MAX_REGEX_LENGTH], [1000], [Maximum length of regex in blacklist file])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_COMMANDS([default],[date > stamp-h ],[])
AC_OUTPUT
