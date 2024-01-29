
/** ***************************************************************************
 *  ***************************************************************************
 *
 * messages.h is part of the project: FILLME 
 * Project Page: https://github.com/tseiman/
 * Author: Thomas Schmidt
 * Copyright (c) 2024 
 *
 * Description:
 *
 * Macros for console messages mainly, including filtering on debug level
 * CLI parameter
 *
 * ****************************************************************************
 * **************************************************************************** **/


#ifndef printf
#include <stdio.h>
#endif


#ifndef MESSAGES_H
#define MESSAGES_H

extern int verbosity;

#define MSG_HELP(command) \
            "\n"                                                              \
            "-h                         Help (this print basically)\n"        \
            "-p                         print JWT\n"                          \
            "-k <pathAndKeyfile>        give path to keyfile\n"               \
            "-v <level 0-3>             verbosity levelv 0= only errors\n"    \
            "                                            1= Info       \n"    \
            "                                            2= Debug      \n"    \
            "                                            3= Memeory Debug\n"  \
            "\n"                                                              \
            "Basic Usage:\n"                                                  \
            "    %s -k key/googleKey-1234.json\n"                             \
            "\n", command


#define PRINT_MSG_HELP_AND_EXIT(command)       printf(MSG_HELP(command)); exit(1);


#define MEM_DBG(_fmt,...)         if(verbosity > 2) fprintf(stdout, "[MEM_DBG] " _fmt "\t(%s:%d)\n", ##__VA_ARGS__  , __FILE__, __LINE__)
#define LOG_DEBUG(_fmt,...)       if(verbosity > 1) fprintf(stdout, "[DEBUG]   " _fmt "\t(%s:%d)\n", ##__VA_ARGS__  , __FILE__, __LINE__)
#define LOG_INFO(_fmt,...)        if(verbosity > 0) fprintf(stdout, "[INFO]    " _fmt "\t(%s:%d)\n", ##__VA_ARGS__  , __FILE__, __LINE__)
#define LOG_ERR(_fmt,...)         fprintf(stderr, "[ERROR]   " _fmt "\t(%s:%d)\n", ##__VA_ARGS__  , __FILE__, __LINE__)

#define STRINGIZE(x) STRINGIZE2(x)
#define STRINGIZE2(x) #x
#define LINE_STRING STRINGIZE(__LINE__)

#define LOG_INFO_MSG_WITH_OK(_fmt,...)        if(verbosity > 0) fprintf(stdout, "[INFO]    " _fmt "... %s", ##__VA_ARGS__, (verbosity > 1 ? "\t("__FILE__":" LINE_STRING ")\n" : ""));
#define LOG_INFO_OK()                         if(verbosity > 0) fprintf(stdout, "OK%s\n",  (verbosity > 1 ? "\t("__FILE__":" LINE_STRING ")\n" : ""))
#define LOG_INFO_FAIL()                       if(verbosity > 0) fprintf(stdout, "FAIL%s\n",(verbosity > 1 ? "\t("__FILE__":" LINE_STRING ")\n" : ""))

#define DBG_PRINT() fprintf(stdout, "[DEBUG PRINT]  %s:%d)\n", __FILE__, __LINE__)


#define TRUE  (1==1)
#define FALSE (!TRUE)

#endif