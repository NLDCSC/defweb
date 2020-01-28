import html
import io
import os
import sys
import time
import urllib.parse
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler

__version__ = '0.0.1'


class DefWebServer(SimpleHTTPRequestHandler):
    server_version = 'DefWebServer/' + __version__
    directory = None

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def version_string(self):
        return self.server_version

    @staticmethod
    def set_server_name(servername):
        DefWebServer.server_version = servername

    def get_file_attr(self, path):

        ret_val = {}

        for entry in os.scandir(path=path):
            ret_val[entry.name] = {
                'uid': entry.stat().st_uid,
                'gid': entry.stat().st_gid,
                'size': entry.stat().st_size,
                'Access time': time.ctime(entry.stat().st_atime),
                'Modified time': time.ctime(entry.stat().st_mtime),
                'Change time': time.ctime(entry.stat().st_ctime)
            }

        return ret_val

    def list_directory(self, path):
        """
        Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().
        """
        if self.directory is not None:
            path = self.directory

        try:
            # list = os.listdir(path)
            dirlist = self.get_file_attr(path=path)
        except OSError:
            self.send_error(
                HTTPStatus.NOT_FOUND,
                "No permission to list directory")
            return None
        # list.sort(key=lambda a: a.lower())
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
                 'content="text/html; charset=%s">' % enc)
        r.append('<title>%s</title>\n</head>' % title)
        r.append('<body>\n<h1>%s</h1>' % title)
        r.append('<table style="width:50%">')
        r.append('<tr><th>Filename</th><th>Size</th><th>Owner</th></tr>')
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
            # r.append('<li><a href="%s">%s</a></li>'
            #          % (urllib.parse.quote(linkname,
            #                                errors='surrogatepass'),
            #             html.escape(displayname)))
            r.append('<tr><td><a href="%s">%s</a></td><td>Smith</td><td>50</td></tr>'
                     % (urllib.parse.quote(linkname,
                                           errors='surrogatepass'),
                        html.escape(displayname)))

        # r.append('</ul>\n</table>\n<hr>\n</body>\n</html>\n')
        r.append('</table>\n<hr>\n</body>\n</html>\n')
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
