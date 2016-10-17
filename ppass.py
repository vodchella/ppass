#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import sqlite3
import traceback
import argparse
import subprocess
from getpass import getpass

# Global variables
DEBUG = False
g_conn = None
g_gpg_id = None
g_parser = None


#
# Error functions
#
def stderr_out(line):
    sys.stderr.write(line)
    sys.stderr.flush()


def get_raised_error():
    if DEBUG:
        return "\n".join(traceback.format_exception(*sys.exc_info()))
    else:
        return traceback.format_exception(*sys.exc_info())[-1:][0]


def panic(msg=None):
    if not msg:
        msg = get_raised_error()
    stderr_out(msg)

    global g_conn
    if g_conn:
        try:
            g_conn.rollback()
        except:
            pass
        g_conn.close()

    sys.exit(1)


def module_not_installed(module_name, project_url, install_command="pip"):
    panic("Module '%(module)s' isn't installed. Install it with 'sudo %(cmd)s install %(module)s' %(url)s\n" %
          {"module": module_name, "url": "(%s)" % project_url if len(project_url) > 0 else "", "cmd": install_command})


#
# Import nonstandart modules
#
last_module = ("sh", "https://github.com/amoffat/sh/")
try:
    # noinspection PyUnresolvedReferences
    from sh import printf, gpg2, base64, date

    last_module = ("at", "", "apt")
    # noinspection PyUnresolvedReferences
    from sh import at

    last_module = ("prettytable", "https://code.google.com/archive/p/prettytable/")
    # noinspection PyUnresolvedReferences
    from prettytable import PrettyTable
except ImportError:
    cmd = "pip" if len(last_module) < 3 else last_module[2]
    module_not_installed(last_module[0], last_module[1], cmd)


#
# Console functions
#
def console_progress_bar(iteration, total, decimals=1, bar_length=100):
    if total == 1:
        return
    format_str = "{0:." + str(decimals) + "f}"
    percents = format_str.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    sys.stdout.write("\r%s |%s| %s%s %s" % ("Progress:", bar, percents, '%', "complete"))
    if iteration == total:
        sys.stdout.write("\n")
    sys.stdout.flush()


def console_print_tree(lst, level=0):
    """
    lst = ['a', ['b', 'c', 'd'], ['e', 'f'], 'g']
    a
    └──b
        └──c
        └──d
    └──e
        └──f
    └──g
    """
    def value_by_type(val):
        return "[\x1b[1;34;40m%s\x1b[0m]" % val[1] if val[0] == 1 else val[1]
    print('    ' * (level - 1) + '└──' * (level > 0) + value_by_type(lst[0]))
    for l in lst[1:]:
        if type(l) is list:
            console_print_tree(l, level + 1)
        else:
            print('    ' * level + '└──' + value_by_type(l))


def console_input_default(prompt, default_value=None):
    result = input(prompt.strip() + " ")
    if not result.strip():
        result = default_value
    return result


def console_input_password(prompt):
    return getpass(prompt.strip() + " ")


#
# GPG2-encryption functions
#
def gpg_encrypt(data, gpg_id=None):
    try:
        global g_gpg_id
        g_id = g_gpg_id if gpg_id is None else gpg_id
        return str(base64(gpg2(printf(data), "-e", "-r", g_id, "--quiet",
                               "--yes", "--compress-algo=none", "--no-encrypt-to",
                               "--batch", "--use-agent", _err=stderr_out)))
    except:
        panic()


def gpg_decrypt(data):
    try:
        return str(gpg2(base64(printf(data), "-d"), "-d", "--quiet",
                        "--yes", "--compress-algo=none", "--no-encrypt-to",
                        "--batch", "--use-agent", _err=stderr_out))
    except:
        panic()


#
# Sqlite3 functions
#
def sqlite_get_one_value(sql, params=None, no_panic=False):
    try:
        global g_conn
        p = [] if params is None else params
        cur = g_conn.cursor()
        cur.execute(sql, p)
        row = cur.fetchone()
        if row:
            return row[0]
    except:
        if not no_panic:
            panic()


#
# Password store functions
#
def store_init(new_gpg_id):
    try:
        global g_conn
        op_cnt = 9
        console_progress_bar(0, op_cnt)
        g_conn.execute("""CREATE TABLE IF NOT EXISTS settings (
                            id	    INTEGER PRIMARY KEY NOT NULL DEFAULT 1 CHECK (id = 1),
                            gpg_id	TEXT,
                            version	NUMERIC
                        );""")
        console_progress_bar(1, op_cnt)
        g_conn.execute("""CREATE TABLE IF NOT EXISTS groups (
                            group_id	     INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                            parent_group_id	 INTEGER,
                            group_name	     TEXT TEXT NOT NULL UNIQUE,
                            FOREIGN KEY (parent_group_id) REFERENCES groups (group_id)
                        );""")
        console_progress_bar(2, op_cnt)
        g_conn.execute("""CREATE TABLE IF NOT EXISTS passwords (
                            password_id	    INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                            deleted_bool	INTEGER NOT NULL DEFAULT 0,
                            group_id	    INTEGER NOT NULL DEFAULT 1,
                            password_name	TEXT NOT NULL CHECK (length(trim(password_name)) > 0),
                            encrypted_value	TEXT NOT NULL CHECK (length(trim(encrypted_value)) > 0),
                            login	        TEXT,
                            description	    TEXT,
                            created_at	    TEXT NOT NULL DEFAULT (strftime('%d.%m.%Y %H:%M:%S', 'now', 'localtime')),
                            FOREIGN KEY (group_id) REFERENCES groups (group_id)
                        );""")
        console_progress_bar(3, op_cnt)
        g_conn.execute("""CREATE TRIGGER IF NOT EXISTS bd_settings BEFORE DELETE ON settings FOR EACH ROW
                          BEGIN
                              SELECT CASE
                                       WHEN OLD.id = 1 THEN
                                           RAISE(FAIL, 'Can''t delete system row')
                                     END;
                          END;""")
        console_progress_bar(4, op_cnt)
        g_conn.execute("""CREATE TRIGGER IF NOT EXISTS bd_groups BEFORE DELETE ON groups FOR EACH ROW
                          BEGIN
                              SELECT CASE
                                       WHEN OLD.group_id = 1 THEN
                                           RAISE(FAIL, 'Can''t delete system row')
                                     END;
                          END;""")
        console_progress_bar(5, op_cnt)
        g_conn.execute("""CREATE TRIGGER IF NOT EXISTS bu_groups BEFORE UPDATE ON groups FOR EACH ROW
                          BEGIN
                              SELECT CASE
                                       WHEN OLD.group_id = 1 THEN
                                           RAISE(FAIL, 'Can''t update system row')
                                     END;
                          END;""")
        console_progress_bar(6, op_cnt)
        g_conn.execute("""CREATE TRIGGER IF NOT EXISTS bi_passwords BEFORE INSERT ON passwords FOR EACH ROW
                          BEGIN
                              UPDATE passwords
                              SET    deleted_bool = 1
                              WHERE  password_id <> NEW.password_id AND
                                     password_name = NEW.password_name AND
                                     group_id = NEW.group_id AND
                                     deleted_bool = 0;
                          END;""")
        console_progress_bar(7, op_cnt)
        g_conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS unq_password ON passwords (group_id, password_name)
                          WHERE deleted_bool = 0;""")
        console_progress_bar(8, op_cnt)
        g_conn.execute("PRAGMA foreign_keys = ON;")
        g_conn.execute("INSERT OR IGNORE INTO groups (group_id, group_name) VALUES (1, '/');")
        g_conn.execute("INSERT OR IGNORE INTO settings (gpg_id, version) VALUES (?, 1);", [new_gpg_id])
        g_conn.commit()
        console_progress_bar(op_cnt, op_cnt)
    except:
        panic()


def store_is_initialized():
    # noinspection SqlResolve
    initialized = sqlite_get_one_value("""SELECT count(*)
                                          FROM   sqlite_master
                                          WHERE  type = 'table' AND
                                                 name = 'settings'""") != 0
    return initialized


def store_reencrypt(new_gpg_id):
    try:
        global g_conn
        global g_gpg_id
        op_cnt = int(sqlite_get_one_value("SELECT count(*) FROM passwords")) + 1
        console_progress_bar(0, op_cnt)
        for rec in enumerate(g_conn.execute("SELECT password_id, encrypted_value FROM passwords"), start=1):
            row = rec[1]
            decrypted_value = gpg_decrypt(row[1])
            encrypted_value = gpg_encrypt(decrypted_value, new_gpg_id)
            g_conn.execute("UPDATE passwords SET encrypted_value = ? WHERE password_id = ?", [encrypted_value, row[0]])
            console_progress_bar(rec[0], op_cnt)
        g_conn.execute("UPDATE settings SET gpg_id = ?", [new_gpg_id])
        g_conn.commit()
        g_gpg_id = new_gpg_id
        console_progress_bar(op_cnt, op_cnt)
    except:
        print("\n")
        panic()


def store_get_gpg_id():
    return sqlite_get_one_value("SELECT gpg_id FROM settings", no_panic=True)


def store_password_exists(password_name, group_id=1):
    return int(sqlite_get_one_value("""SELECT count(*)
                                       FROM   passwords
                                       WHERE  password_name = ? AND
                                              group_id = ? AND
                                              deleted_bool = 0""",
                                    [password_name, group_id])) != 0


def store_save_password(password_name, password_value, group_id=1):
    try:
        global g_conn
        result = False
        encrypted_value = gpg_encrypt(password_value)
        if encrypted_value:
            g_conn.execute("""INSERT INTO passwords (group_id, password_name, encrypted_value, login, description)
                              SELECT ?, ?, ?, login, description
                              FROM   (SELECT password_id, login, description
                                      FROM   passwords
                                      WHERE  password_name = ? AND
                                             group_id = ? AND
                                             deleted_bool = 0
                                      UNION ALL
                                      SELECT 0, NULL, NULL
                                      ORDER BY 1 DESC
                                      LIMIT 1);""",
                           [group_id, password_name, encrypted_value, password_name, group_id])
            g_conn.commit()
            result = True
        return result
    except:
        panic()


def store_get_password(password_name, group_id=1):
    encrypted_value = sqlite_get_one_value("""SELECT encrypted_value
                                              FROM   passwords
                                              WHERE  password_name = ? AND
                                                     group_id = ? AND
                                                     deleted_bool = 0""",
                                           [password_name, group_id])
    if encrypted_value:
        return gpg_decrypt(encrypted_value)


#
# Command line arguments handlers
#
def args_process_init(in_args):
    gpg_id = str(in_args.__getattribute__("gpg-id"))
    try:
        if g_gpg_id:
            store_reencrypt(gpg_id)
            print("Password store reencrypted for %s" % gpg_id)
        else:
            store_init(gpg_id)
            print("Password store initialized for %s" % gpg_id)
    except:
        panic()


def args_process_show(in_args):
    global g_conn
    password_name = str(in_args.__getattribute__("pass-name"))
    if not store_password_exists(password_name):
        stderr_out("Error: %s is not in the password store.\n" % password_name)
    else:
        def _str(val):
            return val if val is not None else ""
        if in_args.history:
            op_cnt = int(sqlite_get_one_value("""SELECT count(*)
                                                 FROM   passwords WHERE
                                                        password_name = ? AND
                                                        group_id = 1""", [password_name]))
            if op_cnt > 1:
                print("Decrypting passwords...")
            table = PrettyTable(["Current", "Password", "Created at", "Login", "Description"])
            console_progress_bar(0, op_cnt)
            for rec in enumerate(g_conn.execute("""SELECT deleted_bool, created_at, login, description, encrypted_value
                                                   FROM   passwords
                                                   WHERE  password_name = ? AND
                                                          group_id = 1
                                                   ORDER BY password_id DESC""", [password_name]), start=1):
                row = rec[1]
                table.add_row(["[x]" if row[0] == 0 else "",
                               gpg_decrypt(row[4]),
                               _str(row[1]),
                               _str(row[2]),
                               _str(row[3])])
                console_progress_bar(rec[0], op_cnt)
            print(table)
        elif in_args.full:
            table = PrettyTable(["Password", "Created at", "Login", "Description"])
            for row in g_conn.execute("""SELECT created_at, login, description, encrypted_value
                                         FROM   passwords
                                         WHERE  password_name = ? AND
                                                deleted_bool = 0 AND
                                                group_id = 1""", [password_name]):
                table.add_row([gpg_decrypt(row[3]),
                               _str(row[0]),
                               _str(row[1]),
                               _str(row[2])])
            print(table)
        else:
            decrypted_password = store_get_password(password_name)
            if in_args.clip:
                p = subprocess.Popen(["xclip", "-d", ":0", "-selection", "c"],
                                     stdin=subprocess.PIPE, close_fds=True)
                p.communicate(input=decrypted_password.encode("utf-8"))
                exec_at = str(date("+%Y%m%d%H%M.%S", date="now +45 seconds")).strip("\n")
                at(printf("printf '' | xclip -d :0 -selection c"), "-t", exec_at)
                print("Copied %s to clipboard. Will clear in 45 seconds." % password_name)
            else:
                print(decrypted_password)


def args_process_ls(in_args=None):
    lst = [(1, "/")]
    global g_conn
    lst += [(2, row[0]) for row in g_conn.execute("""SELECT password_name
                                                     FROM   passwords
                                                     WHERE  group_id = 1 AND
                                                            deleted_bool = 0
                                                     ORDER BY password_name ASC""")]
    console_print_tree(lst)


def args_process_insert(in_args):
    password_name = str(in_args.__getattribute__("pass-name"))
    if not in_args.force and store_password_exists(password_name):
        if console_input_default("An entry already exists for %s. Overwrite it? [y/N]" % password_name, "N")\
                .lower() != "y":
            return
    password = None
    while True:
        password = console_input_password("Enter password for %s:" % password_name)
        confirm = console_input_password("Retype password for %s:" % password_name)
        if password == confirm:
            break
        stderr_out("Error: the entered passwords do not match.\n")
    store_save_password(password_name, password)


#
# Main code
#
def args_parse():
    global g_parser
    g_parser = argparse.ArgumentParser(description="ppass - stores, retrieves and generates passwords securely")
    subparsers = g_parser.add_subparsers()

    parser_append = subparsers.add_parser("init", help="Initialize new password storage and use gpg-id for encryption")
    parser_append.add_argument("gpg-id", help="id of the key generated with gpg2")
    parser_append.set_defaults(func=args_process_init)

    parser_append = subparsers.add_parser("ls", help="List passwords")
    parser_append.add_argument("subfolder", help="Not implemented yet", nargs='*', default="/")
    parser_append.set_defaults(func=args_process_ls)

    parser_append = subparsers.add_parser("insert", help="""Insert a new password into the password store called pass-name.
                                                            This will read the new password from standard in.
                                                            Prompt before overwriting an existing password,
                                                            unless --force or -f is specified""")
    parser_append.add_argument("pass-name", help="Name of the password")
    parser_append.add_argument("--force", "-f", help="Don't prompt before overwriting an existing password",
                               action="store_true")
    parser_append.set_defaults(func=args_process_insert)

    parser_append = subparsers.add_parser("show", help="""Decrypt and print a password named pass-name and
                                                          optionally put it on the clipboard.
                                                          Print full info if --full or -f is specified.
                                                          Print info about old passwords if --history is specified""")
    parser_append.add_argument("pass-name", help="Name of the password")
    parser_append.add_argument("--history", help="Print password history", action="store_true")
    parser_append.add_argument("--full", "-f", help="Print full password info", action="store_true")
    parser_append.add_argument("--clip", "-c", help="Put password on the clipboard for 45 seconds", action="store_true")
    parser_append.set_defaults(func=args_process_show)

    return g_parser.parse_args()


if __name__ == "__main__":
    args = args_parse()
    try:
        g_conn = sqlite3.connect(".ppass-store")
        g_gpg_id = store_get_gpg_id()
    except:
        panic()
    if not g_gpg_id:
        if store_is_initialized():
            panic("Error: password store is corrupted, can''t get gpg-id.\n")
        else:
            if not hasattr(args, "func") or args.func != args_process_init:
                panic("Error: password store is empty. Try \"ppass init\".\n")

    if hasattr(args, "func"):
        args.func(args)
    else:
        args_process_ls()

    if g_conn:
        g_conn.close()
