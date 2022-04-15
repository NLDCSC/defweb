import grp
import html
import io
import logging
import os
import pwd
import sys
import time
import urllib.parse
from collections import namedtuple
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler
from pathlib import Path
from stat import filemode

from defweb.utils.logger_class import HelperLogger

logging.setLoggerClass(HelperLogger)

__version__ = "1.0.2"

# logger = logging.getLogger(__name__)


class DefWebServer(SimpleHTTPRequestHandler):

    protocols = namedtuple("DefWebServerProtocols", ("HTTP", "HTTPS"))(
        "http://", "https://"
    )

    server_version = "DefWebServer/" + __version__

    root_dir = None

    def __init__(self, request, client_address, server):
        self.logger = logging.getLogger(__name__)
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

        # create entry for 1 level up
        # path[:-1] removes trailing '/' in order to facilitate comparing to DefWebServer.root_dir
        if path[:-1] != DefWebServer.root_dir:
            parent = Path(path)

            ret_val[".."] = {
                "uid": parent.stat().st_uid,
                "gid": parent.stat().st_gid,
                "username": pwd.getpwuid(int(parent.stat().st_uid)).pw_name,
                "groupname": grp.getgrgid(int(parent.stat().st_gid)).gr_name,
                "size": parent.stat().st_size,
                "Access time": time.ctime(parent.stat().st_atime),
                "Modified time": time.ctime(parent.stat().st_mtime),
                "Change time": time.ctime(parent.stat().st_ctime),
                "permissions": filemode(parent.stat().st_mode),
            }

        for entry in os.scandir(path=path):
            ret_val[entry.name] = {
                "uid": entry.stat().st_uid,
                "gid": entry.stat().st_gid,
                "username": pwd.getpwuid(int(entry.stat().st_uid)).pw_name,
                "groupname": grp.getgrgid(int(entry.stat().st_gid)).gr_name,
                "size": entry.stat().st_size,
                "Access time": time.ctime(entry.stat().st_atime),
                "Modified time": time.ctime(entry.stat().st_mtime),
                "Change time": time.ctime(entry.stat().st_ctime),
                "permissions": filemode(entry.stat().st_mode),
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
        try:
            dirlist = self.get_file_attr(path=path)
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None
        r = []
        try:
            displaypath = urllib.parse.unquote(self.path, errors="surrogatepass")
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(path)
        displaypath = html.escape(displaypath)
        enc = sys.getfilesystemencoding()
        title = "Directory listing for %s" % displaypath
        r.append(
            '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
            '"http://www.w3.org/TR/html4/strict.dtd">'
        )
        r.append("<html>\n<head>")
        r.append(
            "<style>table, th, td {border: 1px solid black;border-collapse: collapse; padding-left: 10px}"
            "th {text-align: left;background-color: black;color: white;}"
            "tr:nth-child(even) {background-color: #eee;}"
            "tr:nth-child(odd) {background-color: #fff;}</style>"
        )
        r.append(f'<meta http-equiv="Content-Type" content="text/html; charset={enc}">')
        r.append(f"<title>{title}</title>\n</head>")
        r.append("<body>")
        r.append(f"<h1>{title}</h1>")
        r.append('<table style="width:60%">')
        r.append(
            "<tr>"
            "<th>Permissions</th>"
            "<th>Owner</th>"
            "<th>Group</th>"
            "<th>Size</th>"
            "<th>Modified</th>"
            '<th style="width:50%">Filename</th>'
            "</tr>"
        )
        for name in sorted(dirlist.keys()):
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                if displayname != "..":
                    displayname = name + "/"
                    linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # Note: a link to a directory displays with @ and links with /
            r.append(
                '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href="{}">{}</a></td></tr>'.format(
                    dirlist[name]["permissions"],
                    dirlist[name]["username"],
                    dirlist[name]["groupname"],
                    dirlist[name]["size"],
                    dirlist[name]["Modified time"],
                    urllib.parse.quote(linkname, errors="surrogatepass"),
                    html.escape(displayname),
                )
            )

        r.append(
            f"</table>\n<br><hr>\n<h5>{self.server_version}</h5>\n</body>\n</html>\n"
        )
        encoded = "\n".join(r).encode(enc, "surrogateescape")
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    def do_PUT(self):
        """Save a file following an HTTP PUT request"""

        filename = os.path.basename(self.path)

        file_length = int(self.headers["Content-Length"])
        try:
            with open(filename, "wb") as output_file:
                output_file.write(self.rfile.read(file_length))
            self.send_response(201, "Created")
            reply_body = f'Saved "{filename}"\n'
        except PermissionError as err:
            self.send_response(403, "Permission Denied")
            reply_body = f'Could not save "{filename}" to disk. Error: {err}\n'
        self.send_header("Content-Length", str(len(reply_body)))
        self.end_headers()
        self.wfile.write(reply_body.encode("utf-8"))

    def log_message(self, format, *args):
        """
        Log messages via python logging
        """
        self.logger.data(f"{format % args} ", self.address_string())
