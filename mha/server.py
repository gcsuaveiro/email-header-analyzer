from flask import Flask
from flask import render_template
from flask import request

from email.parser import HeaderParser
import time
import dateutil.parser

from datetime import datetime
import re

import pygal
from pygal.style import Style

from IPy import IP
import geoip2.database

import argparse
import subprocess

import whois

import json
import urllib.request

import logging

app = Flask(__name__)
reader = geoip2.database.Reader(
    '%s/data/GeoLite2-Country.mmdb' % app.static_folder)


@app.context_processor
def utility_processor():
    def getCountryForIP(line):
        ipv4_address = re.compile(r"""
            \b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
            (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))\b""", re.X)
        ip = ipv4_address.findall(line)
        if ip:
            ip = ip[0]  # take the 1st ip and ignore the rest
            if IP(ip).iptype() == 'PUBLIC':
                try:
                    r = reader.country(ip).country
                    if r.iso_code and r.name:
                        return {
                            'iso_code': r.iso_code.lower(),
                            'country_name': r.name
                        }
                except:
                    pass
    return dict(country=getCountryForIP)


@app.context_processor
def utility_processor():
    def duration(seconds, _maxweeks=99999999999):
        return ', '.join(
            '%d %s' % (num, unit)
            for num, unit in zip([
                (seconds // d) % m
                for d, m in (
                    (604800, _maxweeks),
                    (86400, 7), (3600, 24),
                    (60, 60), (1, 60))
            ], ['wk', 'd', 'hr', 'min', 'sec'])
            if num
        )
    return dict(duration=duration)


def dateParser(line):
    try:
        r = dateutil.parser.parse(line, fuzzy=True)

    # if the fuzzy parser failed to parse the line due to
    # incorrect timezone information issue #5 GitHub
    except ValueError:
        r = re.findall('^(.*?)\s*(?:\(|utc)', line, re.I)
        if r:
            r = dateutil.parser.parse(r[0])
    return r


def getHeaderVal(h, data, rex='\s*(.*?)\n\S+:\s'):
    r = re.findall('%s:%s' % (h, rex), data, re.X | re.DOTALL | re.I)
    if r:
        return r[0].strip()
    else:
        return None


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # fill mail data with either uploaded file or form, upload has priority
        mail_data = ""
        try:
            # if there is a file upload, read the file, and decode the binary stream
            eml = request.files['file']
            mail_data = eml.read().decode()
        except Exception as e:
            # if anything goes wrong, revert to form
            mail_data = request.form['headers'].strip()

        with open( 'freemail' ) as f:
            emailFree = [ line.rstrip() for line in f ]
        ip_address_list = []
        mail_data = request.form['headers'].strip()
        r = {}
        n = HeaderParser().parsestr(mail_data)
        graph = []
        ip_checked = []
        received = n.get_all('Received')
        if received:
            received = [i for i in received if ('from' in i or 'by' in i)]
        else:
            received = re.findall(
                'Received:\s*(.*?)\n\S+:\s+', mail_data, re.X | re.DOTALL | re.I)
        c = len(received)
        for i in range(len(received)):
            if ';' in received[i]:
                line = received[i].split(';')
            else:
                line = received[i].split('\r\n')
            line = list(map(str.strip, line))
            line = [x.replace('\r\n', ' ') for x in line]
            try:
                if ';' in received[i + 1]:
                    next_line = received[i + 1].split(';')
                else:
                    next_line = received[i + 1].split('\r\n')
                next_line = list(map(str.strip, next_line))
                next_line = [x.replace('\r\n', '') for x in next_line]
            except IndexError:
                next_line = None

            org_time = dateParser(line[-1])
            if not next_line:
                next_time = org_time
            else:
                next_time = dateParser(next_line[-1])

            if line[0].startswith('from'):
                data = re.findall(
                    """
                    from\s+
                    (.*?)\s+
                    by(.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s|$
                    )""", line[0], re.DOTALL | re.X)
                tmp_lista_IP = re.findall( r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", line[0], re.X)
                for x in range( len( tmp_lista_IP ) ):
                    ip_address_list.append( tmp_lista_IP[ x ] )
            else:
                data = re.findall(
                    """
                    ()by
                    (.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s
                    )""", line[0], re.DOTALL | re.X)

            delay = (org_time - next_time).seconds
            if delay < 0:
                delay = 0

            try:
                ftime = org_time.utctimetuple()
                ftime = time.strftime('%m/%d/%Y %I:%M:%S %p', ftime)
                r[c] = {
                    'Timestmp': org_time,
                    'Time': ftime,
                    'Delay': delay,
                    'Direction': [x.replace('\n', ' ') for x in list(map(str.strip, data[0]))]
                }
                c -= 1
            except IndexError:
                pass

        for i in list(r.values()):
            if i['Direction'][0]:
                graph.append(["From: %s" % i['Direction'][0], i['Delay']])
            else:
                graph.append(["By: %s" % i['Direction'][1], i['Delay']])

        totalDelay = sum([x['Delay'] for x in list(r.values())])
        fTotalDelay = utility_processor()['duration'](totalDelay)
        delayed = True if totalDelay else False

        custom_style = Style(
            background='transparent',
            plot_background='transparent',
            font_family='googlefont:Open Sans',
            # title_font_size=12,
        )
        line_chart = pygal.HorizontalBar(
            style=custom_style, height=250, legend_at_bottom=True,
            tooltip_border_radius=10)
        line_chart.tooltip_fancy_mode = False
        line_chart.title = 'Total Delay is: %s' % fTotalDelay
        line_chart.x_title = 'Delay in seconds.'
        for i in graph:
            line_chart.add(i[0], i[1])
        chart = line_chart.render(is_unicode=True)

        summary = {
            'From': n.get('From') or getHeaderVal('from', mail_data),
            'To': n.get('to') or getHeaderVal('to', mail_data),
            'Cc': n.get('cc') or getHeaderVal('cc', mail_data),
            'Subject': n.get('Subject') or getHeaderVal('Subject', mail_data),
            'MessageID': n.get('Message-ID') or getHeaderVal('Message-ID', mail_data),
            'Date': n.get('Date') or getHeaderVal('Date', mail_data),
            'Return': n.get('Return-Path') or getHeaderVal('Return-Path', mail_data),
        }

        security_headers = ['Received-SPF', 'Authentication-Results',
                            'DKIM-Signature', 'ARC-Authentication-Results']

        for x in range( len( ip_address_list ) ):
            web = 'http://ipinfo.io/' + ip_address_list[ x ] + '/json'

            with urllib.request.urlopen( web ) as url:
                ip_address_data = json.loads( url.read().decode() )
            if( ('hostname' not in ip_address_data) ):
                ip_address_data[ 'hostname' ] = 'Unknown'
            if( ('city' not in ip_address_data) ):
                ip_address_data[ 'city' ] = 'Unknown'
            if( ('region' not in ip_address_data) ):
                ip_address_data[ 'region' ] = 'Unknown'
            if( ('country' not in ip_address_data) ):
                ip_address_data[ 'country' ] = 'Unknown'
            if( ('loc' not in ip_address_data) ):
                ip_address_data[ 'loc' ] = '0,0'
            if( ('org' not in ip_address_data) ):
                ip_address_data[ 'org' ] = 'Unknown'
            if( ('postal' not in ip_address_data) ):
                ip_address_data[ 'postal' ] = '0'
            ip_checked.append( Address( ip_address_list[ x ], ip_address_data[ 'hostname' ], ip_address_data[ 'city' ], ip_address_data[ 'region' ], ip_address_data[ 'country' ], ip_address_data[ 'loc' ], ip_address_data[ 'org' ], ip_address_data[ 'postal' ] ) )

        try:
            email = n.get('From') or getHeaderVal('from', mail_data)
            d = email.split('@')[1].replace(">","")
            if d in emailFree:
                summary[ 'email_domain_type' ] = 'Free Email Provider'
            else:
                summary[ 'email_domain_type' ] = 'Standard Email Provider'
            w = whois.query(d , ignore_returncode=1)
            if w:
                wd = w.__dict__
                for k, v in wd.items():
                    summary[ k ] = v
                    if k == 'creation_date':
                        creation_date = datetime.today() - v
                        months = round( creation_date.days / 60 )
                        if months < 12:
                            summary[ 'diff' ] = '( WARNING: ' + str( months ) + ' Months old! )'
                        else:
                            any = round( months / 12 )
                            summary[ 'diff' ] = str( any ) + ' Years'
        except Exception as e:
            logging.exception( e )
            summary[ 'name' ] = 'Error getting value'
            summary[ 'creation_date' ] = 'Error getting value'
            summary[ 'last_updated' ] = 'Error getting value'
            summary[ 'expiration_date' ] = 'Error getting value'
            summary[ 'name_servers' ] = 'Error getting value'
            summary[ 'whois_error'] = str(e)

        security_analysis = n.get('Authentication-Results') or getHeaderVal('Authentication-Results', mail_data)
        security_points = 0
        if security_analysis.find('spf=pass') >= 0:
            summary[ 'SPF' ] = 'OK.'
            security_points += 1
        else:
            if security_analysis.find('spf=') >= 0:
                summary[ 'SPF' ] = 'WARNING'
                security_points -= 2
            else:
                summary[ 'SPF' ] = 'WARNING: Without SPF'

        if security_analysis.find('dkim=pass') >= 0:
            summary[ 'DKIM' ] = 'OK.'
            security_points += 1
        else:
            if security_analysis.find('dkim=') >= 0:
                summary[ 'DKIM' ] = 'WARNING'
                security_points -= 2
            else:
                summary[ 'DKIM' ] = 'WARNING: Without DKIM'

        if security_analysis.find('dmarc=pass') >= 0:
            summary[ 'DMARC' ] = 'OK.'
            security_points += 1
        else:
            if security_analysis.find('dmarc=') >= 0:
                summary[ 'DMARC' ] = 'WARNING'
                security_points -= 2
            else:
                summary[ 'DMARC' ] = 'WARNING: Without DMARC'

        summary[ 'security_result' ] = str( round( (security_points / 3) * 100, 2 ) ) + '%'

        return render_template(
            'index.html', data=r, delayed=delayed, summary=summary,
            n=n, chart=chart, security_headers=security_headers, ip_checked=ip_checked)
    else:
        return render_template('index.html')

class Address:
  def __init__(self, ip_address, hostname = 'unknown', city = 'unknown', region = 'unknown', country = 'unknown', gps = 'unknown', organization = 'unknown', postal_code = 'unknown' ):
    self.ip_address = ip_address
    self.hostname = hostname
    self.city = city
    self.region = region
    self.country = country
    self.gps = gps
    self.organization = organization
    self.postal_code = postal_code

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Mail Header Analyser")
    parser.add_argument("-d", "--debug", action="store_true", default=False,
                        help="Enable debug mode")
    parser.add_argument("-b", "--bind", default="127.0.0.1", type=str)
    parser.add_argument("-p", "--port", default="8080", type=int)
    args = parser.parse_args()

    app.debug = args.debug
    app.config['UPLOAD_FOLDER']	= "."
    app.config['MAX_CONTENT-PATH'] = 100000
    app.run(host=args.bind, port=args.port)
