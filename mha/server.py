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
                r = reader.country(ip).country
                if r.iso_code and r.name:
                    return {
                        'iso_code': r.iso_code.lower(),
                        'country_name': r.name
                    }
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
        lista_IP = []
        mail_data = request.form['headers'].strip()
        r = {}
        n = HeaderParser().parsestr(mail_data)
        graph = []
        iP_Analizado = []
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
                    lista_IP.append( tmp_lista_IP[ x ] )
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
        line_chart.title = 'Tiempo total: %s' % fTotalDelay
        line_chart.x_title = 'Tiempo en segundos.'
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
                            'DKIM-Signature', 'ARC-Authentication-Results' ]

        for x in range( len( lista_IP ) ):
            web = 'http://ipinfo.io/' + lista_IP[ x ] + '/json'
            with urllib.request.urlopen( web ) as url:
                datos_ip = json.loads( url.read().decode() )
            if( ('hostname' not in datos_ip) ):
                datos_ip[ 'hostname' ] = 'Desconocido'
            if( ('city' not in datos_ip) ):
                datos_ip[ 'city' ] = 'Desconocida'
            if( ('region' not in datos_ip) ):
                datos_ip[ 'region' ] = 'Desconocida'
            if( ('country' not in datos_ip) ):
                datos_ip[ 'country' ] = 'Desconocido'
            if( ('loc' not in datos_ip) ):
                datos_ip[ 'loc' ] = '0,0'
            if( ('org' not in datos_ip) ):
                datos_ip[ 'org' ] = 'Desconocida'
            if( ('postal' not in datos_ip) ):
                datos_ip[ 'postal' ] = '0'
            iP_Analizado.append( Address( lista_IP[ x ], datos_ip[ 'hostname' ], datos_ip[ 'city' ], datos_ip[ 'region' ], datos_ip[ 'country' ], datos_ip[ 'loc' ], datos_ip[ 'org' ], datos_ip[ 'postal' ] ) )

        try:
            email = n.get('From') or getHeaderVal('from', mail_data)
            d = email.split('@')[1].replace(">","")            
            w = whois.query(d , ignore_returncode=1)
            if w:
                wd = w.__dict__
                for k, v in wd.items():
                    summary[ k ] = v        # SE RELLENAN LOS DATOS DE WHOIS  __DICT__
                    if k == 'creation_date':
                        fecha = datetime.today() - v
                        meses = round( fecha.days / 60 )
                        if meses < 12:
                            summary[ 'diff' ] = ' ( PELIGRO ' + str( meses ) + ' MESES DE VIDA!!!! )'
                        else:
                            any = round( meses / 12 )
                            summary[ 'diff' ] = str( any ) + ' Años'
        except Exception as e:
            print( e )
            summary[ 'name' ] = 'ERROR AL BUSCAR'
            summary[ 'creation_date' ] = 'ERROR AL BUSCAR'
            summary[ 'last_updated' ] = 'ERROR AL BUSCAR'
            summary[ 'expiration_date' ] = 'ERROR AL BUSCAR'
            summary[ 'name_servers' ] = 'ERROR AL BUSCAR'

        analiza = n.get('Authentication-Results') or getHeaderVal('Authentication-Results', mail_data)
        puntuacion = 0
        if analiza.find('spf=pass') >= 0:
            summary[ 'SPF' ] = 'OK.'
            puntuacion += 1
        else:
            if analiza.find('spf=') >= 0:
                summary[ 'SPF' ] = 'PELIGRO !!!!!! ( MUCHO CUIDADO )'
                puntuacion -= 2
            else:
                summary[ 'SPF' ] = ' SIN SEGURIDAD ( REVISA QUE EL EL ORIGEN Y A DONDE SE RETORNA EL MAIL )'

        if analiza.find('dkim=pass') >= 0:
            summary[ 'DKIM' ] = 'OK.'
            puntuacion += 1
        else:
            if analiza.find('dkim=') >= 0:
                summary[ 'DKIM' ] = 'PELIGRO !!!!!! ( MUCHO CUIDADO )'
                puntuacion -= 2
            else:
                summary[ 'DKIM' ] = ' SIN SEGURIDAD ( REVISA QUE EL EL ORIGEN Y A DONDE SE RETORNA EL MAIL )'

        if analiza.find('dmarc=pass') >= 0:
            summary[ 'DMARC' ] = 'OK.'
            puntuacion += 1
        else:
            if analiza.find('dmarc=') >= 0:
                summary[ 'DMARC' ] = 'PELIGRO !!!!!! ( MUCHO CUIDADO )'
                puntuacion -= 2
            else:
                summary[ 'DMARC' ] = ' SIN SEGURIDAD ( REVISA QUE EL EL ORIGEN Y A DONDE SE RETORNA EL MAIL )'

        summary[ 'resultado_seguridad' ] = str( round( (puntuacion / 3) * 100, 2 ) ) + '%'

        return render_template(
            'index.html', data=r, delayed=delayed, summary=summary,
            n=n, chart=chart, security_headers=security_headers, iP_Analizado=iP_Analizado)
    else:
        return render_template('index.html')

class Address:
  def __init__(self, iP, hostname = 'desconocido', ciudad = 'desconocido', region = 'desconocido', pais = 'desconocido', gps = 'desconocido', empresa = 'desconocido', cp = 'desconocido' ):
    self.iP = iP
    self.hostname = hostname
    self.ciudad = ciudad
    self.region = region
    self.pais = pais
    self.gps = gps
    self.empresa = empresa
    self.cp = cp

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Mail Header Analyser")
    parser.add_argument("-d", "--debug", action="store_true", default=False,
                        help="Enable debug mode")
    parser.add_argument("-b", "--bind", default="0.0.0.0", type=str)
    parser.add_argument("-p", "--port", default="8080", type=int)
    args = parser.parse_args()

    app.debug = args.debug
    app.run(host=args.bind, port=args.port)