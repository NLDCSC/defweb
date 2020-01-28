import grp
import html
import io
import os
import pwd
import sys
import time
import urllib.parse
from collections import namedtuple
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler
from stat import filemode
from defweb import _version_from_git_describe

__version__ = _version_from_git_describe()


class DefWebServer(SimpleHTTPRequestHandler):

    protocols = namedtuple('DefWebServerProtocols', ('HTTP', 'HTTPS'))('http://', 'https://')

    server_version = 'DefWebServer/' + __version__
    directory = None

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def version_string(self):
        """
        Method to return the version string

        :return: Server version string
        :rtype: str
        """
        return self.server_version

    @staticmethod
    def set_server_name(servername):
        """
        Method to set the server name to a given string

        :param servername: Server name to announce in http headers
        :type servername: str
        """
        DefWebServer.server_version = servername

    @staticmethod
    def get_file_attr(path):
        """
        Method to retrieve file attributes from a given path.

        :param path: Path to scan
        :type path: str
        :return: Dictionary with file attributes
        :rtype: dict
        """

        ret_val = {}

        for entry in os.scandir(path=path):
            ret_val[entry.name] = {
                'uid': entry.stat().st_uid,
                'gid': entry.stat().st_gid,
                'username': pwd.getpwuid(int(entry.stat().st_uid)).pw_name,
                'groupname': grp.getgrgid(int(entry.stat().st_gid)).gr_name,
                'size': entry.stat().st_size,
                'Access time': time.ctime(entry.stat().st_atime),
                'Modified time': time.ctime(entry.stat().st_mtime),
                'Change time': time.ctime(entry.stat().st_ctime),
                'permissions': filemode(entry.stat().st_mode)
            }

        return ret_val

    def list_directory(self, path):
        """
        Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        :param path: Path to directory for listing
        :type path: str
        :return: Directory listing in html
        :rtype: io.BytesIO
        """
        if self.directory is not None:
            path = self.directory

        try:
            dirlist = self.get_file_attr(path=path)
        except OSError:
            self.send_error(
                HTTPStatus.NOT_FOUND,
                "No permission to list directory")
            return None
        r = []
        try:
            displaypath = urllib.parse.unquote(self.path,
                                               errors='surrogatepass')
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(path)
        displaypath = html.escape(displaypath)
        enc = sys.getfilesystemencoding()
        title = 'Directory listing for %s' % displaypath
        r.append('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
                 '"http://www.w3.org/TR/html4/strict.dtd">')
        r.append('<html>\n<head>')
        r.append('<style>table, th, td {border: 1px solid black;border-collapse: collapse; padding-left: 10px}'
                 'th {text-align: left;background-color: black;color: white;}'
                 'tr:nth-child(even) {background-color: #eee;}'
                 'tr:nth-child(odd) {background-color: #fff;}</style>')
        r.append('<meta http-equiv="Content-Type" '
                 'content="text/html; charset={}">'.format(enc))
        r.append('<title>{}</title>\n</head>'.format(title))
        r.append('<body>')
        r.append('<h1>{}</h1>'.format(title))
        r.append('<table style="width:60%">')
        r.append('<tr>'
                 '<th>Permissions</th>'
                 '<th>Owner</th>'
                 '<th>Group</th>'
                 '<th>Size</th>'
                 '<th>Modified</th>'
                 '<th style="width:50%">Filename</th>'
                 '</tr>')
        # r.append('<hr>\n<ul>')
        for name in sorted(dirlist.keys()):
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # Note: a link to a directory displays with @ and links with /
            r.append('<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href="{}">{}</a></td></tr>'
                     .format(dirlist[name]['permissions'], dirlist[name]['username'], dirlist[name]['groupname'],
                             dirlist[name]['size'], dirlist[name]['Modified time'],
                             urllib.parse.quote(linkname, errors='surrogatepass'), html.escape(displayname)))

        r.append('</table>\n<br><hr>\n<h5>{}</h5>\n</body>\n</html>\n'.format(self.server_version))
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    def do_PUT(self):
        """Save a file following a HTTP PUT request"""

        if self.directory is not None:
            filename = os.path.join(self.directory, os.path.basename(self.path))
        else:
            filename = os.path.basename(self.path)

        file_length = int(self.headers['Content-Length'])
        with open(filename, 'wb') as output_file:
            output_file.write(self.rfile.read(file_length))
        self.send_response(201, 'Created')
        reply_body = 'Saved "{}"\n'.format(filename)
        self.send_header("Content-Length", str(len(reply_body)))
        self.end_headers()
        self.wfile.write(reply_body.encode('utf-8'))
