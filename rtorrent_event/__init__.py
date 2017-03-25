#!/usr/bin/python3.5

# NOTES:
# * Various features require 3.5+
# * to install inotify library https://github.com/dsoprea/PyInotify
#   (i.e. https://pypi.python.org/pypi/inotify)
#   pip3 install --user inotify
#   git clone; cd; python3.5 setup.py install --user
# * same with daemons (optional unless --daemon used)
#   https://github.com/kevinconway/daemons
#   https://pypi.python.org/pypi/daemons
#   pip3 install --user daemons

# TODO:
# * add config file?
# * deal with duplicate hash's across trackers?
# * if anything is in the retry queue, we'll never handle removed torrents. Not
#   sure if that is right or not.
# * make an exception class and use it with errors so as not to break out of
#   loop except when an unexpected exception occurs
# * better logging, especially with --clean
# * better torrent bdecoding (i.e. keys etc to strings)
# * use better transaction handling to speed up insertions
# * add lock file (maybe daemon takes care of this?); untested


#sys.argv.extend(('-v', '-v', '-v', '-r', '-n', '~/.config/rtorrent/session', '~/files', '~/seed'))
import argparse
import logging
import os
import re
import sqlite3
import string
import time

from collections import deque, namedtuple, OrderedDict
from math import ceil
from pathlib import Path, PosixPath
from urllib.parse import urlparse

from inotify.adapters import Inotify
from inotify.constants import IN_CREATE, IN_DELETE

# not available in 3.5 on whatbox, fuck these people, and no pip
#from chardet import detect


LOG_FILE = "~/.config/rtorrent_event/event.log"
SQL_FILE = "~/.config/rtorrent_event/file.db"
HOOK_FILE = "~/.config/rtorrent_event/hooks.py"
PID_FILE = "~/.local/var/run/rtorrent_event.pid"
SLEEP_TIME = 3 #seconds

def adapt_path(path):
    "Convert PosixPath to appropriate type for sqlite, i.e. a string"
    return str(path).encode('utf-8')

def convert_path(s):
    "from bytes from sqlite db to PosixPath"
    return PosixPath(s.decode('utf-8'))

sqlite3.register_adapter(Path, adapt_path)
sqlite3.register_adapter(PosixPath, adapt_path)
sqlite3.register_converter("path", convert_path)

class rTorEventException(Exception):
    pass

class rTorFileNotFoundError(rTorEventException):
    pass

RmTuple = namedtuple('RmTuple',
                     ('name', 'tracker', 'hash', 'rmfiles', 'torfiles', 'tor',
                      'ltor', 'rtor'))

def parse_args():
    p = argparse.ArgumentParser(
        description="Scan folders and rtorrent session, removing unused files.")
    p.add_argument('session', action='store',
                   help="rtorrent session folder location.")
    p.add_argument('paths', nargs='*', action='store', default=(),
               help="Paths to remove files from and/or check db against.")
    me = p.add_mutually_exclusive_group()
    me.add_argument('--clean', action='store_true',
            help="""
                    Scan the FS and DB for conflicting information and remove
                    rows from DB to make consistent. Rtorrent needs to not be
                    running or will exit without action, unless --force given.
                    Cannot be run in daemon mode. Use with --remove to remove
                    orphaned files (files on disk but not in db). Paths are
                    required when specified.
                 """)
    me.add_argument('-d', '--daemon', action='store_true',
           help="""
                   Fork off to a daemon, implies "--sleep --log '%s'",
                   unless --log/--sleep are specified.
                """ % LOG_FILE)
    p.add_argument('-f', '--force', action='store_true',
       help="Clean up even if rtorrent is running.")
    p.add_argument('--log-file', action='store', default=None,
                   help="What file to use as log file, defaults to stderr.")
    p.add_argument('-n', '--no-action', action='store_true',
           help="""
                   Print what would happen, but do not execute. Cannot use
                   --daemon.
                """)
    p.add_argument('-r', '--remove', action='store_true',
           help="""
                   Remove files on disk if no longer in db, during normal
                   operation or in --clean. This is effectively the last
                   pre_remove hook run before removing data from database. By
                   default, any "orphaned" files are removed, but if paths
                   arguments are specified, only files in those directories
                   that are orphaned will be removed. "Orphaned" means that
                   the files are no longer associated with any torrents.
                """)
    p.add_argument('--sleep', action='store', type=int, default=SLEEP_TIME,
           help="""
                   How long to sleep when no fs action is detected (seconds).
                   Default: %(default)s
                """)
    p.add_argument('--sql-file', action='store', default=SQL_FILE,
                   help="Where to store history. Default: %(default)s")
    p.add_argument('-v', '--verbose', action='count', default=0,
                   help="Enable higher verbosity levels (up to 4 times).")
    p.add_argument('--hooks', nargs='?', action='store', default=None,
                   const=HOOK_FILE,
            help="""
                    A file of python code with hook functions to run. If
                    argument specified without argument, '%s' is used as the
                    hook file. See README for details on the hooks. 
                 """ % HOOK_FILE)
    args = p.parse_args()
    args.paths = tuple(Path(x).expanduser().resolve() for x in args.paths)
    args.session = Path(args.session).expanduser()
    args.sql_file = Path(args.sql_file).expanduser()
    if not args.session.is_dir():
        p.error("Session directory must exist and be a directory.")
    if not all(x.is_dir() for x in args.paths):
        p.error("Paths must exist and be a directories.")
    if args.daemon and args.no_action:
        p.error("Can only specify one of --no-action and --daemon.")
    if args.daemon and args.log_file is None:
        args.log_file = str(Path(LOG_FILE).expanduser())
    if args.hooks:
        args.hooks = Path(args.hooks).expanduser()
        if not args.hooks.exists():
            p.error("Hook file must exist if specified.")
    if args.clean and not args.paths:
        p.error("Paths must be specified with --clean.")
    return args

def decode_to_path(*pathparts, enc=None):
    "sequence of bytes objects to Path object, decoding using enc/utf-8"
    enc = enc if enc is not None else 'utf-8'
    return Path(*[part.decode(enc) for part in pathparts])

def is_parent(parent, child):
    "is candidate parent an actual parent of child (Paths or strings"
    return os.path.commonpath((str(parent), str(child))) == str(parent)

def bdecode(s):
    """
    Decodes given bencoded bytes object. yanked from github

    >>> decode(b'i-42e')
    -42
    >>> decode(b'4:utku') == b'utku'
    True
    >>> decode(b'li1eli2eli3eeee')
    [1, [2, [3]]]
    >>> decode(b'd3:bar4:spam3:fooi42ee') == {b'bar': b'spam', b'foo': 42}
    True
    """
    def decode_first(s):
        if s.startswith(b"i"):
            match = re.match(b"i(-?\\d+)e", s)
            return int(match.group(1)), s[match.span()[1]:]
        elif s.startswith(b"l") or s.startswith(b"d"):
            l = []
            rest = s[1:]
            while not rest.startswith(b"e"):
                elem, rest = decode_first(rest)
                l.append(elem)
            rest = rest[1:]
            if s.startswith(b"l"):
                return l, rest
            else:
                return {i: j for i, j in zip(l[::2], l[1::2])}, rest
        elif any(s.startswith(i.encode()) for i in string.digits):
            m = re.match(b"(\\d+):", s)
            length = int(m.group(1))
            rest_i = m.span()[1]
            start = rest_i
            end = rest_i + length
            return s[start:end], s[end:]
        else:
            raise ValueError("Malformed input.")
    if isinstance(s, str):
        raise ValueError("Must be a bytes object.")
    ret, rest = decode_first(s)
    if rest:
        raise ValueError("Malformed input.")
    return ret

def tabnew_line_join(objs):
    "join objs with newline, prepending each line with tab"
    return '\n'.join('\t%s' % str(x) for x in objs)

def build_fs_file_set(*paths):
    "Return a set of PosixPath objects representing the files in paths"
    s = set()
    for path in paths:
        for pd, ds, fs in os.walk(str(path)):
            s.update(Path(pd, f).resolve() for f in fs)
    return s

def get_tor_meta(base_torrent_file, args):
    "return name, tracker, and list of files associated with base_torent_file"
    with open(str(base_torrent_file), 'rb') as fd:
        tord = bdecode(fd.read())
    single_file_torrent = b'files' not in tord[b'info']
    with open(str(base_torrent_file) + '.rtorrent', 'rb') as fd:
        rtord = bdecode(fd.read())
    #enct = detect(tord[b'info'][b'name'])['encoding']
    #encrt = detect(rtord[b'directory'])['encoding']
    try:
        base_dir = decode_to_path(rtord[b'directory']).expanduser().resolve()
    except FileNotFoundError:
        raise rTorFileNotFoundError("No data found for: %s" %
                                    base_torrent_file.stem)
    name = tord[b'info'][b'name'].decode('utf-8')
    trackerp = urlparse(tord[b'announce'])
    tracker = (trackerp.hostname if trackerp.hostname
               else trackerp.netloc).decode('utf-8')
    # in multi file torrents, rtorrent adds the name to the base_dir already
    if single_file_torrent:
        return name, tracker, [base_dir / name]
    else:
        return name, tracker, [base_dir / decode_to_path(*file[b'path'])
                               for file in tord[b'info'][b'files']]

def create_tables(file):
    "create sqlite db at file, creating subdirectories if necessary"
    logging.debug("Creating database tables and indexes at '%s'." % str(file))
    os.makedirs(str(file.parent), exist_ok=True)
    conn = sqlite3.connect(str(file))
    with conn:
        conn.execute('''
                    CREATE TABLE torrent_data (
                        hash text PRIMARY KEY,
                        name text,
                        tracker text,
                        torrent blob,
                        libtorrent blob,
                        rtorrent blob
                     );''')
        conn.execute('''
                    CREATE TABLE session_files (
                        hash text NOT NULL,
                        file path NOT NULL,
                        PRIMARY KEY (hash, file),
                        FOREIGN KEY (hash) REFERENCES torrent_data(hash)
                     );''')
        conn.execute('''CREATE INDEX sff ON session_files(file);''')
        conn.execute('''CREATE INDEX sfh ON session_files(hash);''')
    conn.commit()
    conn.close()

def populate_session_tbl(con, sessfldr, no_action, args=None):
    "populate db with rtorrent session files found in sessfldr"
    for file in sessfldr.glob('*.torrent'):
        try:
            name, tracker, torfiles = get_tor_meta(file, args)
        except rTorFileNotFoundError:
            logging.warning("No data found for hash: %s" % file.stem)
            continue
        add_new_session_file(con, file, name, tracker, torfiles, no_action,
                             args=args, commit=False, exists='debug')
    if not no_action:
        con.commit()

def add_new_session_file(con, file, name, tracker, tor_files, no_action,
                         args=None, commit=True, exists='warn'):
    "add session file found at file with name, tracker, and file list to db"
    hash = file.stem
    with con:
        c = con.execute('SELECT 1 FROM torrent_data WHERE hash = ?', (hash,))
        if c.fetchall():
            c.close()
            logger = getattr(logging, exists)
            logger("Hash already present: %s" % hash)
            return
        c.close()
    logging.info("Adding hash, name, tracker to db: %s, '%s', %s" %
                 (hash, name, tracker))
    tf_str = "Adding files:\n%s" % tabnew_line_join(tor_files)
    if no_action:
        print(tf_str)
        return
    logging.debug(tf_str)
    with con:
        with open(str(file), 'rb') as fd:
            tord = fd.read()
        with open(str(file.with_suffix('.torrent.libtorrent_resume')), 'rb') as fd:
            ltord = fd.read()
        with open(str(file.with_suffix('.torrent.rtorrent')), 'rb') as fd:
            rtord = fd.read()
        con.execute("""
            INSERT INTO torrent_data
                (hash, name, tracker, torrent, libtorrent, rtorrent)
                VALUES (?, ?, ?, ?, ?, ?);
                """, (hash, name, tracker, tord, ltord, rtord))
        con.executemany('INSERT INTO session_files (hash, file) VALUES (?, ?)',
                        ((hash, tf) for tf in tor_files))
    if commit:
        con.commit()

def check_rtorrent_running(sessiondir, force):
    "check if running, raise if force is False and running."
    lock_file = sessiondir / 'rtorrent.lock'
    rt_running = lock_file.exists()
    if not rt_running:
        return True
    if force and rt_running:
        logging.warning("Rtorrent is still running, but continuing.")
        return False
    elif not force and rt_running:
        raise SystemExit("Rtorrent is still running. -f to force.")

def qfunc_create(con, path, args, queues):
    logging.debug("Processing file: %s" % str(path))
    try:
        hooks_and_add_torrent(con, path, args)
    except rTorFileNotFoundError:
        logging.warning("No data found for: %s" % path.stem)
        queues['retry_create'].append(path)

def qfunc_retry_create(con, path, args, queues):
    try:
        hooks_and_add_torrent(con, path, args)
    except rTorFileNotFoundError:
        queues['retry_create'].append(path)

def handle_remove_torrent(con, file, no_action, args=None):
    """
        remove torrent associated with session file from db

        run rm_file_hook if args.remove is True
    """
    hash = file.stem
    try:
        c = con.execute('''SELECT name, tracker, torrent, libtorrent, rtorrent
                            FROM torrent_data WHERE hash = ?''', (hash,))
        name, tracker, tor, ltor, rtor = c.fetchall()[0]
        # all files associated with torrent
        c.execute('SELECT file FROM session_files WHERE hash = ?', (hash,))
        torfiles = [x for (x,) in c.fetchall()]
    except IndexError:
        logging.error("Hash to remove not in db: %s" % hash)
        raise rTorEventException("Hash to remove not in db: %s" % hash)
    else:
        logging.info("Remove hash, name, tracker from db: %s, '%s', %s" %
                     (hash, name, tracker))
        if args.remove:
            rmfiles = rm_file_hook(con, file, args)
        else:
            rmfiles = []
    finally:
        c.close()
    with con:
        con.execute('DELETE FROM session_files WHERE hash = ?;', (hash,))
        con.execute('DELETE FROM torrent_data WHERE hash = ?;', (hash,))
    con.commit()
    return RmTuple(name, tracker, hash, rmfiles, torfiles, tor, ltor, rtor)

def rm_file_hook(con, file, args):
    """
        remove files associated with session file file from disk.

        if args.paths is non-empty, files must be a child of one path
    """
    hash = file.stem
    # which files do not have a match
    c = con.execute('''SELECT f.file FROM
                       session_files f
                       LEFT JOIN session_files s
                       ON s.file = f.file AND s.hash <> f.hash
                       WHERE s.file IS NULL AND f.hash = ?;''', (hash,))
    rmfiles = [x for (x,) in c.fetchall()
               if not args.paths or any(is_parent(p, x) for p in args.paths)]
    c.execute('SELECT count(*) FROM session_files WHERE hash = ?', (hash,))
    file_count = c.fetchall()[0][0]
    c.close()
    if args.no_action:
        print("Remove files:\n%s" % tabnew_line_join(rmfiles))
        return rmfiles
    success = deque()
    for file in rmfiles:
        try:
            logging.debug("Remove files: '%s'" % str(file))
            file.unlink()
        except (OSError, IOError) as e:
            logging.exception("Could not remove file: '%s'" % str(file))
        else:
            success.append(file)
    logging.info("File counts for hash %s removed/removable/rotal: %d/%d/%d" %
                 (hash, len(success), len(rmfiles), file_count))
    return list(success)

def remove_missing_hashes(con, sessfldr, no_action, args=None):
    fs_hashes = set(f.stem for f in sessfldr.glob('*.torrent'))
    with con:
        c = con.execute('SELECT DISTINCT hash, name, tracker FROM torrent_data;')
        db_hash_data = {x[0]:x[1:] for x in c.fetchall()}
        c.close()
    rm_hashes = db_hash_data.keys() - fs_hashes
    rm_data = ["%s, '%s', %s" % t for t in
               sorted([(k, *db_hash_data[k]) for k in rm_hashes],
                     key=lambda x: x[1])]
    if no_action:
        print("Remove hashes from db:\n%s" % tabnew_line_join(rm_data))
        return rm_hashes
    with con:
        logging.info("Remove hashes from db:\n%s" % tabnew_line_join(rm_hashes))
        con.executemany('DELETE FROM session_files WHERE hash = ?',
                        ((h,) for h in rm_hashes))
        con.executemany('DELETE FROM torrent_data WHERE hash = ?',
                        ((h,) for h in rm_hashes))
    return rm_hashes

def clean_tables(con, no_action, fs_file_set, args=None):
    "Remove files in db not found on fs."
    with con:
        c = con.execute('SELECT DISTINCT file FROM session_files;')
        db_file_set = {x for (x,) in c.fetchall()}
        c.close()
    with con:
        rmfiles = sorted(db_file_set - fs_file_set)
        if no_action:
            print("Remove from session: '%s'" % tabnew_line_join(rmfiles))
            return
        logging.info("Remove from session: '%s'" % tabnew_line_join(rmfiles))
        try:
            if rmfiles:
                c = con.execute("DELETE FROM session_files WHERE file IN (%s)" %
                                ', '.join(('?') * len(rmfiles)), rmfiles)
                rmcount = c.rowcount
                c.close()
            else:
                rmcount = 0
        except sqlite3.Error as e:
            logging.exception("Error while removing from session_files")

        else:
            logging.debug("Removed %d rows from session_files" % rmcount)
        try:
            hashrm = con.execute("""DELETE FROM torrent_data WHERE hash IN
                           (SELECT t.hash FROM torrent_data t
                            LEFT JOIN session_files s ON s.hash = t.hash
                            WHERE s.hash IS NULL);
                        """).rowcount
        except sqlite3.Error as e:
            logging.exception("Error removing from torrent_data")
            hashrm = -1
        logging.info("Removed %d rows from torrent_data table" % hashrm)
    con.commit()

def remove_orphan_files(con, no_action, fs_file_set, args=None):
    "remove files on disk not found in db"
    with con:
        c = con.execute('SELECT DISTINCT file FROM session_files;')
        db_file_set = {x for (x,) in c.fetchall()}
        c.close()
    for file in fs_file_set - db_file_set:
        if args.paths and not any(is_parent(p, file) for p in args.paths):
            continue
        if no_action:
            print("Remove from fs: '%s'" % str(file))
            continue
        try:
            logging.info("Remove from fs: '%s'" % str(file))
            file.unlink()
        except (OSError, IOError) as e:
            logging.exception("Could not remove from fs: '%s'" % str(file))

def prune_empty_directories(*dirs):
    "Delete a tree of empty directories, will not delete dirs passed in."
    for dir in dirs:
        for d, ds, fs in os.walk(str(dir), topdown=False):
            if d == dir:
                break
            try:
                os.rmdir(d)
            except OSError:
                pass
            else:
                logging.info("Removed empty directory: '%s'" % d)

def import_user(file):
    "import a user python file that is not on path as if it were a module"
    import importlib.machinery
    import importlib.util
    logging.debug("Import %s" % str(file))
    loader = importlib.machinery.SourceFileLoader('hooks', str(file))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    hooks = importlib.util.module_from_spec(spec)
    loader.exec_module(hooks)
    return hooks

def hooks_and_add_torrent(con, path, args):
    "handle a new torrent file by running hooks and adding to db"
    name, tracker, torfiles = get_tor_meta(path, args)
    hook = getattr(hooks, 'pre_add', None)
    if hook:
        logging.debug("Running pre_add.")
        hook(con, path, args)
    add_new_session_file(con, path, name, tracker, torfiles, args.no_action,
                         args=args)
    hook = getattr(hooks, 'post_add', None)
    if hook:
        logging.debug("Running post_add.")
        hook(con, path, args)

def hooks_and_remove_torrent(con, path, args, queues):
    """
        handle new removal of a torrent file by running hooks, removing from db

        rm files if args.remove is True via rm_file_hook
    """
    logging.debug("Removed file: %s" % str(path))
    hook = getattr(hooks, 'pre_remove', None)
    if hook:
        logging.debug("Running pre_remove.")
        hook(con, path, args)
    rmtup = handle_remove_torrent(con, path, args.no_action, args=args)
    hook = getattr(hooks, 'pre_remove', None)
    if hook:
        logging.debug("Running post_remove.")
        hook(con, path, args, rmtup)

def inotify_loop(con, inot, args, queues, qfuncs, inot_funcs):
    "loop over inotify event generator and dispatch as necessary"
    for event in inot.event_gen():
        if event is None:
            for key in queues:
                if queues[key]:
                    f = queues[key].popleft()
                    qfuncs[key](con, f, args, queues)
                    break
            else:
                logging.debug("Sleeping for %d" % args.sleep)
                time.sleep(args.sleep) # sleep only when nothing to do
            continue
        header, type_names, watch_path, filename = event
        logging.debug("EVENT: %s" % (event,))
        if filename.lower().endswith(b'.new'):
            filename = filename[:-4]
        path = decode_to_path(watch_path, filename)
        inot_key = (path.name.split('.')[-1], tuple(type_names))
        if inot_key in inot_funcs:
            inot_funcs[inot_key](path)

def inotify(args):
    "Setup to run inotify loop"
    inot = Inotify()
    inot.add_watch(bytes(args.session), mask=IN_CREATE ^ IN_DELETE)
    global hooks
    if args.hooks:
        hooks = import_user(args.hooks)
    else:
        hooks = None
    try:
        con = sqlite3.connect(str(args.sql_file),
                              detect_types=sqlite3.PARSE_DECLTYPES)
        logging.info("Repopulating database.")
        populate_session_tbl(con, args.session, args.no_action, args=args)
        queues = OrderedDict((('create',deque()),
                              ('retry_create',deque()),
                              ('remove',deque())))
        qfuncs = {'create':qfunc_create,
                  'retry_create':qfunc_retry_create,
                  'remove':hooks_and_remove_torrent}
        inot_funcs = {('torrent', ('IN_CREATE',)) : queues['create'].append,
                      ('torrent', ('IN_DELETE',)) : queues['remove'].append
                     }
        complete_hook = getattr(hooks, 'complete', None)
        if complete_hook:
            queues['complete'] = deque()
            inot_funcs[('complete', ('IN_CREATE',))] = queues['complete'].append
            qfuncs['complete'] = complete_hook
        logging.info("Entering inotify loop.")
        preloop_hook = getattr(hooks, 'pre_loop', None)
        if preloop_hook:
            preloop_hook(con, inot, args, queues, qfuncs, inot_funcs)
        queues.move_to_end('remove')
        while True:
            try:
                inotify_loop(con, inot, args, queues, qfuncs, inot_funcs)
            except rTorEventException as e:
                logging.exception("Something happened.")
            except (KeyboardInterrupt, SystemExit):
                logging.info("Exiting due to interrupt.")
                raise
            except Exception:
                logging.exception("Unhandled exception.")
                raise
    finally:
        postloop_hook = getattr(hooks, 'post_loop', None)
        if postloop_hook:
            postloop_hook(con, inot, args)
        inot.remove_watch(bytes(args.session))
        con.close()

def clean(args):
    """
        make sure db synced with fs, and fs with db if args.remove is True.

        preferably with rtorrent not running
    """
    con = sqlite3.connect(str(args.sql_file),
                          detect_types=sqlite3.PARSE_DECLTYPES)
    check_rtorrent_running(args.session, args.force)
    populate_session_tbl(con, args.session, args.no_action, args=args)
    remove_missing_hashes(con, args.session, args.no_action, args=args)
    fs_file_set = build_fs_file_set(*args.paths)
    clean_tables(con, args.no_action, fs_file_set, args=args)
    if args.remove:
        remove_orphan_files(con, args.no_action, fs_file_set, args=args)
        if not args.no_action:
            prune_empty_directories(*args.paths)
    if not args.no_action:
        logging.debug("Vacuum database.")
        con.execute('VACUUM;')
    con.commit()
    con.close()

def main(args):
    "do work depending on args"
    if args.clean:
        clean(args)
    elif args.daemon:
        from daemons import daemonizer
        dmn = daemonizer.run(pidfile=str(Path(PID_FILE).expanduser()))(inotify)
        dmn(args)
    else:
        inotify(args)

