#!/usr/bin/python3.5

# INSTALL:
# pip3 install git+https://github.com/lostnihilist/rtorrent_event --user

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
# * make logging work before and after daemonizing things so we get the PID in
#   the log file too
# * fix resolve usages
# * add config file?
# * deal with duplicate hash's across trackers?
# * if anything is in the retry queue, we'll never handle removed torrents. Not
#   sure if that is right or not.
# * make an exception class and use it with errors so as not to break out of
#   loop except when an unexpected exception occurs
# * better logging, especially with --clean
# * better torrent bdecoding (i.e. keys etc to strings)
#   https://github.com/lostnihilist/bencode.py
#   https://github.com/fuzeman/bencode.py
# * use better transaction handling to speed up insertions?


#sys.argv.extend(('-v', '-v', '-v', '-r', '-n', '~/.config/rtorrent/session', '~/files', '~/seed'))
import argparse
import logging
import math
import os
import re
import sqlite3
import string
import sys
import time

from collections import deque, namedtuple, OrderedDict
from math import ceil
from pathlib import Path, PosixPath
from urllib.parse import urlparse

import bencode

from inotify.adapters import Inotify
from inotify.constants import IN_CREATE, IN_DELETE

# not available in 3.5 on whatbox, fuck these people, and no pip
#from chardet import detect


LOG_FILE = Path("~/.config/rtorrent_event/event.log")
SQL_FILE = Path("~/.config/rtorrent_event/file.db")
HOOK_FILE = "~/.config/rtorrent_event/hooks.py"
PID_FILE = Path("~/.local/var/run/rtorrent_event.pid").expanduser()
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
    p.add_argument('--log-file', action='store', default=LOG_FILE,
                   help="What file to use as log file, defaults to %s." %
                        str(LOG_FILE))
    p.add_argument('--no-log', action='store_true',
                   help="do not write a log file.")
    p.add_argument('-q', '--quiet', action='store_true',
           help="suppress output on stdout/stderr. Does not effect log file.")
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
    p.add_argument('--sql-file', action='store', default=SQL_FILE, type=Path,
                   help="Where to store history. Default: %s" % str(SQL_FILE))
    p.add_argument('-v', '--verbose', action='count', default=0,
                   help="Enable higher verbosity levels (up to 4 times).")
    p.add_argument('--hooks', nargs='?', action='store', default=None,
                   const=HOOK_FILE,
            help="""
                    A file of python code with hook functions to run. If
                    argument specified without argument, '%s' is used as the
                    hook file. See README for details on the hooks. 
                 """ % HOOK_FILE)
    p.add_argument('--clean-lockfile', action='store_true',
                   help="Remove a lockfile. I DO NOT CHECK IF IT IS STALE!")
    args = p.parse_args()
    args.paths = tuple(Path(x).expanduser().resolve() for x in args.paths)
    args.session = Path(args.session).expanduser()
    args.sql_file = args.sql_file.expanduser()
    if not args.session.is_dir():
        p.error("Session directory must exist and be a directory.")
    if not all(x.is_dir() for x in args.paths):
        p.error("Paths must exist and be a directories.")
    if args.daemon and args.no_action:
        p.error("Can only specify one of --no-action and --daemon.")
    args.log_file = args.log_file.expanduser() if not args.no_log else None
    if args.hooks:
        args.hooks = Path(args.hooks).expanduser()
        if not args.hooks.exists():
            p.error("Hook file must exist if specified.")
    if args.clean and not args.paths:
        p.error("Paths must be specified with --clean.")
    return args

def is_parent(parent, child):
    "is candidate parent an actual parent of child (Paths or strings"
    return os.path.commonpath((str(parent), str(child))) == str(parent)

def common_parent(*files, are_absolute=False):
    """
        get the deepest directory common to all files/directories.

        all files must exist while call is executing
    """
    if not files:
        return None
    if not are_absolute:
        files = [x.absolute() for x in files]
    base_dir = files[0] if files[0].is_dir() else files[0].parent
    for cmpfile in files:
        for i, (bp, cp) in enumerate(zip(base_dir.parts, cmpfile.parts)):
            if bp != cp:
                if i < 0:
                    return None
                # have to map from parts idx to parents idx, annoying
                parent_idx = len(base_dir.parts) - 1 - i
                base_dir = base_dir.parents[parent_idx]
    return base_dir

def tabnew_line_join(objs):
    "join objs with newline, prepending each line with tab"
    return '\n'.join('\t%s' % str(x) for x in objs)

def human_filesize(size, binary=True, digits=1, unit=None, bits=False,
                   inbinary=True, inunit='', inbits=False):
    """
        convert number of bytes to human readable size as string

        binary: use 1024 system. False to use decimal. iB versus B in output
        digits: how many digits after decimal point to report
        unit: None to determine automatically, else one of KMGTPEZ,
              '' for Bytes.
        bits: output in bits or bytes (default: bytes) (b vs B in output)
        inbinary: input in binary, applies only if inunit != ''
        inunit: '' for bytes, KMGTPEZ for higher order
        inbits: is the input in bits or bytes. default bytes
    """
    fmt = "%%1.%df %%s%%s" % digits
    units = ('', 'K', 'M', 'G', 'T', 'P', 'E', 'Z')
    divsuf = [(1000, 'B'), (1024, 'iB')]
    size *= divsuf[inbinary][0]**units.index(inunit) / (1,8)[inbits]*(1,8)[bits]
    div, suf = divsuf[binary]
    if size <= 0: # log(0) undefined
        unit = ''
    unit = (unit if unit is not None else
            units[min(math.floor(math.log(size, div)), len(units)-1)])
    size /= div ** units.index(unit)
    unit = unit if unit != 'K' or binary else 'k' # strictly, in SI k not K
    suf = 'B' if unit == '' else suf
    suf = suf.lower() if bits else suf
    return fmt % (size, unit, suf)

def build_fs_file_set(*paths):
    "Return a set of PosixPath objects representing the files in paths"
    s = set()
    for path in paths:
        for pd, ds, fs in os.walk(str(path)):
            s.update(Path(pd, f).resolve() for f in fs)
    return s

def get_tor_meta(base_torrent_file, args):
    "return name, tracker, and list of files associated with base_torent_file"
    tord = bencode.bread(str(base_torrent_file))
    rtord = bencode.bread(str(base_torrent_file) + '.rtorrent')
    try:
        base_dir = Path(rtord['directory']).expanduser().resolve()
    except FileNotFoundError:
        raise rTorFileNotFoundError("No data found for: %s" %
                                    base_torrent_file.stem)
    single_file_torrent = 'files' not in tord['info']
    name = tord['info']['name']
    if "announce" in tord:
        trackerp = urlparse(tord['announce'])
        tracker = trackerp.hostname if trackerp.hostname else trackerp.netloc
    elif "announce-list" in tord:
        trackerp = urlparse(tord['announce-list'][0][0])
        tracker = trackerp.hostname if trackerp.hostname else trackerp.netloc
    else:
        tracker = "No Tracker"
    # in multi file torrents, rtorrent adds the name to the base_dir already
    if single_file_torrent:
        return name, tracker, [base_dir / name]
    else:
        return name, tracker, [base_dir / Path(*file['path'])
                               for file in tord['info']['files']]

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
        except bencode.BencodeDecodeError:
            logging.error("Invalid torrent data for hasth: %s" % file.stem)
            continue
        add_new_session_file(con, file, name, tracker, torfiles, no_action,
                             args=args, commit=False)
    if not no_action:
        con.commit()

def add_new_session_file(con, file, name, tracker, tor_files, no_action,
                         args=None, commit=True):
    "add session file found at file with name, tracker, and file list to db"
    hash = file.stem
    with con:
        c = con.execute('SELECT 1 FROM torrent_data WHERE hash = ?', (hash,))
        if c.fetchall():
            c.close()
            logging.debug("Hash already present: %s" % hash)
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
    except IndexError as e:
        raise e
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
    done_rmfiles, rmsize = rm_files(rmfiles, args.no_action, args.paths)
    fmt_str = "Rm stats for hash %s removed/removable/total/size: %d/%d/%d/%s"
    if args.no_action:
        print(fmt_str % (hash, len(done_rmfiles), len(rmfiles), file_count,
                         human_filesize(rmsize)))
    else:
        logging.info(fmt_str % (hash, len(done_rmfiles), len(rmfiles),
                                file_count, human_filesize(rmsize)))
    return(done_rmfiles)

def remove_missing_hashes(con, sessfldr, no_action, args=None):
    fs_hashes = set(f.stem for f in sessfldr.glob('*.torrent'))
    with con:
        c = con.execute('SELECT DISTINCT hash, name, tracker FROM torrent_data;')
        db_hash_data = {x[0]:x[1:] for x in c.fetchall()}
        c.close()
    rm_hashes = db_hash_data.keys() - fs_hashes
    if not rm_hashes:
        return rm_hashes
    rm_data = ["%s, '%s', %s" % t for t in
               sorted([(k, *db_hash_data[k]) for k in rm_hashes],
                     key=lambda x: x[1])]
    if no_action:
        print("Remove hashes from db:\n%s" % tabnew_line_join(rm_data))
        return rm_hashes
    with con:
        logging.info("Remove hashes from db:\n%s" % tabnew_line_join(rm_data))
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
    rmfiles = sorted(db_file_set - fs_file_set)
    with con:
        if rmfiles:
            if no_action:
                print("Remove from session:\n'%s'" % tabnew_line_join(rmfiles))
                return
            logging.info("Remove from session:\n'%s'" % tabnew_line_join(rmfiles))
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

def rm_files(files, no_action, parent_paths, log_level='debug'):
    """
        rm sequence of files and return list of files and total size removed

        no_action: just print what would happen
        parent_paths: only remove if the file is in one of the listed parent paths
        log_level: at what level log level to print normal file rm op
    """
    logger = getattr(logging, log_level)
    success, rm_size = deque(), 0
    com_par = common_parent(*files)
    for file in files:
        if parent_paths and not any(is_parent(p, file) for p in parent_paths):
            continue
        if no_action:
            print("Remove from fs: '%s'" % str(file))
            success.append(file)
            rm_size += file.stat().st_size
            continue
        try:
            logger("Remove from fs: '%s'" % str(file))
            fsize = file.stat().st_size
            file.unlink()
        except (OSError, IOError) as e:
            logging.exception("Could not remove file from fs: '%s'" % str(file))
        else:
            success.append(file)
            rm_size += fsize
    else:
        if (com_par is not None and not no_action and parent_paths and
                        any(is_parent(p, com_par) for p in parent_paths)):
            try:
                com_par.rmdir()
            except (OSError, PermissionError):
                pass
            else:
                logger("Removed dir from fs: '%s'" % str(com_par))
                success.appendleft(com_par)
    return list(success), rm_size

def remove_orphan_files(con, no_action, fs_file_set, args=None):
    "remove files on disk not found in db"
    with con:
        c = con.execute('SELECT DISTINCT file FROM session_files;')
        db_file_set = {x for (x,) in c.fetchall()}
        c.close()
    rm_files(sorted(fs_file_set - db_file_set), no_action, args.paths, 'info')

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
    try:
        name, tracker, torfiles = get_tor_meta(path, args)
    except FileNotFoundError:
        return False
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
    return True

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
    try:
        rmtup = handle_remove_torrent(con, path, args.no_action, args=args)
    except IndexError:
        logging.error("Hash to remove not in db: %s" % path.stem)
    else:
        hook = getattr(hooks, 'pre_remove', None)
        if hook:
            logging.debug("Running post_remove.")
            hook(con, path, args, rmtup)

def setup_logging(args):
    formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
    rootlog = logging.getLogger()
    loglevel = logging.ERROR - 10 * args.verbose
    rootlog.setLevel(loglevel)
    if not args.quiet and not args.daemon:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        console.setLevel(loglevel)
        rootlog.addHandler(console)
    if args.log_file:
        logfile = logging.FileHandler(str(args.log_file))
        logfile.setFormatter(formatter)
        logfile.setLevel(loglevel)
        rootlog.addHandler(logfile)
    if args.quiet and not args.log_file:
        rootlog.disabled = True

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
        if filename.lower().endswith('.new'):
            filename = filename[:-4]
        path = Path(watch_path, filename)
        inot_key = (path.suffix[1:], tuple(type_names))
        if inot_key in inot_funcs:
            inot_funcs[inot_key](path)

def inotify(args):
    "Setup to run inotify loop"
    setup_logging(args)
    inot = Inotify()
    inot.add_watch(str(args.session), mask=IN_CREATE ^ IN_DELETE)
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

def inotify_withlock(args, lockfile_path):
    try:
        lockfile = open(str(lockfile_path), 'x')
        lockfile.write(str(os.getpid()))
        lockfile.close()
    except FileExistsError:
        logging.error("Lock file exists. "
              "Check to see if another instance is running. "
              "If not, run with --clean-lockfile to remove the stale lockfile.",
              file=sys.stderr)
        exit(1)
    else:
        inotify(args)
    finally:
        lockfile_path.unlink()

def clean(args, lockfile_path):
    """
        make sure db synced with fs, and fs with db if args.remove is True.

        preferably with rtorrent not running
    """
    setup_logging(args)
    try:
        lockfile = open(str(lockfile_path), 'x')
        lockfile.write(str(os.getpid()))
        lockfile.close()
    except FileExistsError:
        logging.error("Lock file exists. "
              "Check to see if another instance is running. "
              "If not, run with --clean-lockfile to remove the stale lockfile.")
        exit(1)
    else:
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
    finally:
        lockfile_path.unlink()

def main(args):
    "do work depending on args"
    lockfile_path = PID_FILE
    if args.clean_lockfile and lockfile_path.exists():
        lockfile_path.unlink()
    if args.clean:
        clean(args, lockfile_path)
    elif args.daemon:
        from daemons import daemonizer
        dmn = daemonizer.run(pidfile=str(PID_FILE))(inotify)
        dmn(args)
    else:
        inotify_withlock(args, lockfile_path)

