#coding:UTF-8
__author__ = 'dj'

from app import app
from flask import render_template, request, flash, redirect, url_for, send_from_directory
from forms import Upload, ProtoFilter
from utils.upload_tools import allowed_file, get_filetype, random_name
from utils.pcap_decode import PcapDecode
from utils.pcap_filter import get_all_pcap, proto_filter, showdata_from_id
from utils.proto_analyzer import common_proto_statistic, pcap_len_statistic, http_statistic, dns_statistic, most_proto_statistic
from utils.flow_analyzer import time_flow, data_flow, get_host_ip, data_in_out_ip, proto_flow, most_flow_statistic
from utils.ipmap_tools import getmyip, get_ipmap, get_geo
from utils.data_extract import web_data, telnet_ftp_data, mail_data, sen_data
from utils.except_info import exception_warning
from utils.file_extract import web_file, ftp_file, mail_file, all_files
from scapy.all import rdpcap
import os

#Import the function into the template
app.jinja_env.globals['enumerate'] = enumerate

#Global variables
PCAP_NAME = ''     #Upload file name
PD = PcapDecode()  #Parser
PCAPS = None       #data pack

#--------------------------------------------------------Home, upload---------------------------------------------
#Home
@app.route('/', methods=['POST', 'GET'])
@app.route('/index/', methods=['POST', 'GET'])
def index():
    return render_template('./home/index.html')


#Packet upload
@app.route('/upload/', methods=['POST', 'GET'])
def upload():
    upload = Upload()
    if request.method == 'GET':
        return render_template('./upload/upload.html')
    elif request.method == 'POST':
        pcap = upload.pcap.data
        if upload.validate_on_submit():
            pcapname = pcap.filename
            if allowed_file(pcapname):
                name1 = random_name()
                name2 = get_filetype(pcapname)
                global PCAP_NAME, PCAPS
                PCAP_NAME = name1 + name2
                try:
                    pcap.save(os.path.join(app.config['UPLOAD_FOLDER'], PCAP_NAME))
                    PCAPS = rdpcap(os.path.join(app.config['UPLOAD_FOLDER'], PCAP_NAME))
                    flash('Congratulations, upload success！')
                    return render_template('./upload/upload.html')
                except Exception as e:
                    flash('Upload error, error message:' + str(e))
                    return render_template('./upload/upload.html')
            else:
                flash('Upload failed, please upload the allowed packet format!')
                return render_template('./upload/upload.html')
        else:
            return render_template('./upload/upload.html')


#-------------------------------------------数据分析----------------------------------------------------
#basic data
@app.route('/basedata/', methods=['POST', 'GET'])
def basedata():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        filter = ProtoFilter()
        filter_type = filter.filter_type.data
        value = filter.value.data
        if value and filter_type:
            pcaps = proto_filter(filter_type, value, PCAPS, PD)
        else:
            pcaps = get_all_pcap(PCAPS, PD)
        return render_template('./dataanalyzer/basedata.html', pcaps=pcaps)

PDF_NAME = ''
#detailed data
@app.route('/datashow/', methods=['POST', 'GET'])
def datashow():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        global PDF_NAME
        dataid = request.args.get('id')
        dataid = int(dataid) - 1
        data = showdata_from_id(PCAPS, dataid)
        PDF_NAME = random_name() + '.pdf'
        PCAPS[dataid].pdfdump(app.config['PDF_FOLDER'] + PDF_NAME)
        return data

#Save the packet as pdf
@app.route('/savepdf/', methods=['POST', 'GET'])
def savepdf():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        return send_from_directory(app.config['PDF_FOLDER'], PDF_NAME, as_attachment=True)


#Agreement Analysis
@app.route('/protoanalyzer/', methods=['POST', 'GET'])
def protoanalyzer():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        data_dict = common_proto_statistic(PCAPS)
        pcap_len_dict = pcap_len_statistic(PCAPS)
        pcap_count_dict = most_proto_statistic(PCAPS, PD)
        http_dict = http_statistic(PCAPS)
        http_dict = sorted(http_dict.iteritems(), key=lambda d:d[1], reverse=False)
        http_key_list = list()
        http_value_list = list()
        for key, value in http_dict:
            http_key_list.append(key)
            http_value_list.append(value)
        dns_dict = dns_statistic(PCAPS)
        dns_dict = sorted(dns_dict.iteritems(), key=lambda d:d[1], reverse=False)
        dns_key_list = list()
        dns_value_list = list()
        for key, value in dns_dict:
            dns_key_list.append(key)
            dns_value_list.append(value)
        return render_template('./dataanalyzer/protoanalyzer.html', data=data_dict.values(), pcap_len=pcap_len_dict, pcap_count=pcap_count_dict, http_key=http_key_list, http_value=http_value_list, dns_key=dns_key_list, dns_value=dns_value_list)

#Traffic Analysis
@app.route('/flowanalyzer/', methods=['POST', 'GET'])
def flowanalyzer():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        time_flow_dict = time_flow(PCAPS)
        host_ip = get_host_ip(PCAPS)
        data_flow_dict = data_flow(PCAPS, host_ip)
        data_ip_dict = data_in_out_ip(PCAPS, host_ip)
        proto_flow_dict = proto_flow(PCAPS)
        most_flow_dict = most_flow_statistic(PCAPS, PD)
        most_flow_dict = sorted(most_flow_dict.iteritems(), key=lambda d:d[1], reverse=True)
        if len(most_flow_dict) > 10:
            most_flow_dict = most_flow_dict[0:10]
        most_flow_key = list()
        for key, value in most_flow_dict:
            most_flow_key.append(key)
        return render_template('./dataanalyzer/flowanalyzer.html', time_flow=time_flow_dict, data_flow=data_flow_dict, ip_flow=data_ip_dict, proto_flow=proto_flow_dict.values(), most_flow_key=most_flow_key, most_flow_dict=most_flow_dict)

#Visit the map
@app.route('/ipmap/', methods=['POST', 'GET'])
def ipmap():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        myip = getmyip()
        if myip:
            host_ip = get_host_ip(PCAPS)
            ipdata = get_ipmap(PCAPS, host_ip)
            geo_dict = ipdata[0]
            ip_value_list = ipdata[1]
            myip_geo = get_geo(myip)
            return render_template('./dataanalyzer/ipmap.html', geo_data=geo_dict, ip_value=ip_value_list, mygeo=myip_geo)
        else:
            return render_template('./error/neterror.html')

# ----------------------------------------------Data extraction page---------------------------------------------

#Web data
@app.route('/webdata/', methods=['POST', 'GET'])
def webdata():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        dataid = request.args.get('id')
        host_ip = get_host_ip(PCAPS)
        webdata_list = web_data(PCAPS, host_ip)
        if dataid:
            return webdata_list[int(dataid)-1]['data'].replace('\r\n', '<br>')
        else:
            return render_template('./dataextract/webdata.html', webdata=webdata_list)

#Mail data
@app.route('/maildata/', methods=['POST', 'GET'])
def maildata():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        dataid = request.args.get('id')
        host_ip = get_host_ip(PCAPS)
        mailata_list = mail_data(PCAPS, host_ip)
        if dataid:
            return mailata_list[int(dataid)-1]['data'].replace('\r\n', '<br>')
        else:
            return render_template('./dataextract/maildata.html', maildata=mailata_list)

#FTP data
@app.route('/ftpdata/', methods=['POST', 'GET'])
def ftpdata():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        dataid = request.args.get('id')
        host_ip = get_host_ip(PCAPS)
        ftpdata_list = telnet_ftp_data(PCAPS, host_ip, 21)
        if dataid:
            return ftpdata_list[int(dataid)-1]['data'].replace('\r\n', '<br>')
        else:
            return render_template('./dataextract/ftpdata.html', ftpdata=ftpdata_list)

#Telnet data
@app.route('/telnetdata/', methods=['POST', 'GET'])
def telnetdata():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        dataid = request.args.get('id')
        host_ip = get_host_ip(PCAPS)
        telnetdata_list = telnet_ftp_data(PCAPS, host_ip, 23)
        if dataid:
            return telnetdata_list[int(dataid)-1]['data'].replace('\r\n', '<br>')
        else:
            return render_template('./dataextract/telnetdata.html', telnetdata=telnetdata_list)

#Sensitive data
@app.route('/sendata/', methods=['POST', 'GET'])
def sendata():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        dataid = request.args.get('id')
        host_ip = get_host_ip(PCAPS)
        sendata_list = sen_data(PCAPS, host_ip)
        if dataid:
            return sendata_list[int(dataid)-1]['data'].replace('\r\n', '<br>')
        else:
            return render_template('./dataextract/sendata.html', sendata=sendata_list)

# ----------------------------------------------An unusual information page---------------------------------------------

#abnormal data
@app.route('/exceptinfo/', methods=['POST', 'GET'])
def exceptinfo():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        dataid = request.args.get('id')
        host_ip = get_host_ip(PCAPS)
        warning_list = exception_warning(PCAPS, host_ip)
        if dataid:
            if warning_list[int(dataid)-1]['data']:
                return warning_list[int(dataid)-1]['data'].replace('\r\n', '<br>')
            else:
                return '<center><h3>No related packet details</h3></center>'
        else:
            return render_template('./exceptions/exception.html', warning=warning_list)

# ----------------------------------------------File extraction---------------------------------------------
#WEB file extraction
@app.route('/webfile/', methods=['POST', 'GET'])
def webfile():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        host_ip = get_host_ip(PCAPS)
        web_list = web_file(PCAPS, host_ip, app.config['FILE_FOLDER'] + 'Web/')
        file_dict = dict()
        for web in web_list:
            file_dict[os.path.split(web['filename'])[-1]] = web['filename']
        file = request.args.get('file')
        if file in file_dict:
            return send_from_directory(app.config['FILE_FOLDER'] + 'Web/', file.encode('utf-8'), as_attachment=True)
        else:
            return render_template('./fileextract/webfile.html', web_list=web_list)

#Mail file extraction
@app.route('/mailfile/', methods=['POST', 'GET'])
def mailfile():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        host_ip = get_host_ip(PCAPS)
        mail_list = mail_file(PCAPS, host_ip, app.config['FILE_FOLDER'] + 'Mail/')
        file_dict = dict()
        for mail in mail_list:
            file_dict[os.path.split(mail['filename'])[-1]] = mail['filename']
        file = request.args.get('file')
        if file in file_dict:
            return send_from_directory(app.config['FILE_FOLDER'] + 'Mail/', file, as_attachment=True)
        else:
            return render_template('./fileextract/mailfile.html', mail_list=mail_list)


#FTP file extraction
@app.route('/ftpfile/', methods=['POST', 'GET'])
def ftpfile():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        host_ip = get_host_ip(PCAPS)
        ftp_list = ftp_file(PCAPS, host_ip, app.config['FILE_FOLDER'] + 'FTP/')
        file_dict = dict()
        for ftp in ftp_list:
            file_dict[os.path.split(ftp['filename'])[-1]] = ftp['filename']
        file = request.args.get('file')
        if file in file_dict:
            return send_from_directory(app.config['FILE_FOLDER'] + 'FTP/', file, as_attachment=True)
        else:
            return render_template('./fileextract/ftpfile.html', ftp_list=ftp_list)

#All binary extraction
@app.route('/allfile/', methods=['POST', 'GET'])
def allfile():
    if PCAPS == None:
        flash("Please upload the packet to be analyzed first!")
        return redirect(url_for('upload'))
    else:
        allfiles_dict = all_files(PCAPS, app.config['FILE_FOLDER'] + 'All/')
        file = request.args.get('file')
        if file in allfiles_dict:
            return send_from_directory(app.config['FILE_FOLDER'] + 'All/', file, as_attachment=True)
        else:
            return render_template('./fileextract/allfile.html', allfiles_dict=allfiles_dict)


# -------------------------------------------Packet Construction page------------------------------------------
#Agreement Description
@app.route('/nettools/', methods=['POST', 'GET'])
def nettools():
    return 'Network tools'



# ----------------------------------------------Error handling page---------------------------------------------
@app.errorhandler(404)
def internal_error(error):
    return render_template('./error/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('./error/500.html'), 500
