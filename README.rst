An event loop based off inotify events in rtorrent's session directory.


Hooks
____

Only one basic hook is provided, and that can be initiated with -r to remove
files associated with a torrent that are not found in any other torrents.
Because we use the file hash, and multiple torrents can contain the same hash,
this is still not fully robust.

There are hooks that act before/after a torrent is added to or removed from the
database, a hook that runs before the main program loop starts and one that runs
after it has finished (to allow you to do any necessary cleanups), and then a
hook that allows you to run when a torrent is completed if you make an
appropriate handler in rtorrent to signify completion events.

pre/post add hooks (pre_add, post_add):
    function signature (con, file, args) where con is the sqlite database
    connection, file is a Path object specifying what torrent file is added,
    and args is the argparse object detailing runtime options. The pre/post
    refer to preadding the data to the database and then after that event. The
    torrent has of course already been added to rtorrent.

pre_remove:
    function signature (con, file, args). This is pre-removal of information
    about this torrent from the database. It has already been removed from
    rtorrent.

post_remove:
    function signature (con, file, args, RmTuple). RmTuple contains info
    stored in db as well as what files were associated with the torrent,
    and if -r was specified, what files were able to be removed.
    'RmTuple' is a namedtuple of (name, tracker, hash, rmfiles, torfiles, tor,
    ltor, rtor), i.e.:

   - name: name of the torrent,
   - tracker: the tracker hostname associated with the torrent,
   - hash: the hash of the torrent,
   - rmfiles: the files that were in fact removed (with -n, that would have been
     removed; without --remove, this is empty list. Does not include files that
     we tried to remove but failed to for logged reason.),
   - torfiles: the files associated with the torrent,
   - tor: the torrent,
   - ltor: libtorrent, and
   - rtor: rtorrent bencoded data pulled from the db for you before deleting

Finally, if you setup rtorrent to create a file <HASH>.complete in the rtorrent
session directory when a file is completed, a hook named 'complete' will be
run with signature (con, path, args, queues). Completed files are added to
the queues dict under key 'complete'.

There is also a hook that is run before the program starts listening for
changes 'pre_loop' with signature pre_loop(con, inot, args, queues, qfuncs,
inot_funcs) where:

- con is the db connection,
- inot is an inotify.Inotify instance,
- args are the runtime arguments,
- queues is an OrderedDict of queues to which you can add file paths as inotify
  events are received,
- qfuncs are functions with signature(con, path, args, queues)
- inotify_funcs is a dict where the key is a tuple (fileext, type_tuple) of
  what event has occurred and the value is a function taking the Path of the
  file detected by inotify. The fileext is the text after the last '.' in the
  filename of the given inotify event, with '.new' stripped from it.

The idea with the pre_loop is that you can add inotify event handlers based on the
event type and extension, and add a queue to the queue dict with an associated
function in the qfuncs dict. You have access to the db to create/modify tables
as you deem necessary.

'post_loop' is run as the program is exiting (either due to an unexpected
exception or due to a signal) 'post_loop' which take arguments con, inot, args.
If you add inotify watches, this would be where to remove them.


DB Tables
---------

torrent_data:

- hash (primary key): torrent hash as text, all upper case
- name: text, torrent name
- tracker: text, torrent tracker domain
- torrent: blob, bencoded data from original torrent
- libtorrent: blob, bencoded data from the initially seen .libtorrent_resume
  session file
- rtorrent: blob, bencoded data from the initially seen .rtorrent session file

session_file:

- hash (PK, FK -> torrent_data.hash, indexed): text
- file (PK, indexed): 'binary text', i.e. utf-8 encoded text. with the DB
  opened with the appropriate adapters, this is read as a PosixPath object


These are not updated in the table after the initial torrent creation; so do
not contain updated stats/completion status/etc. These are not available in the
table with pre_add or post_remove.

Make sure to commit any database changes. Hooks are not called when initially
populating or cleaning the db. Data may generally be unreliable or unavailable
when no-action is used.

