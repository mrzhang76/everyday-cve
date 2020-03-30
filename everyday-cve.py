#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
from bs4 import BeautifulSoup
import re
import datetime
import os
import pymysql


headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Upgrade-Insecure-Requests': '1',
}


class CveObject:
    cve_no = ''                     # 漏洞编号
    cve_nvd_url = ''                # 漏洞nvd url链接地址
    cve_description = ''            # 漏洞描述
    cve_level = ''                  # 威胁等级
    cve_score = ''                  # 威胁评分
    cve_cna = ''                    # 漏洞分配的机构

    def show(self):
        """
        Show basic vul information
        :return: None
        """
        print('----------------------------------')
        print('编号：', self.cve_no)
        print('漏洞描述：', self.cve_description)
        print('漏洞等级：', self.cve_level)
        print('漏洞评分：', self.cve_score)
        print('\n\n')


url = "https://cassandra.cerias.purdue.edu/CVE_changes/today.html"
cve_obj_list = []           # cve obj-s fill with detailed information
today = datetime.date.today()


def get_cve_urls():
    start_content = 'New entries'  # 起始字符串
    end_content = 'Graduations'
    response = requests.get(url, headers=headers, timeout=60)
    response = str(response.text)
    start_index = response.index(start_content)
    if start_index >= 0:
        start_index += len(start_content)
        end_index = response.index(end_content)
        cve_urls_content = response[start_index:end_index]  # 获取网页的指定范围
        soup = BeautifulSoup(cve_urls_content, 'lxml')
        cve_url_lists = []  # 存放获取到的cve url

        for u in soup.find_all('a'):
            cve_url = u["href"]
            cve_url_lists.append(cve_url)

        return cve_url_lists


def fill_with_nvd(cve, cve_obj):
    """
    Fetch detailed information by search cve to fill cve_obj that can be fetch from NVD
    :param cve: cve no
    :param cve_obj: cve object to fill
    :return: None
    """
    cve_obj.cve_no = cve

    nvd_url = 'https://nvd.nist.gov/vuln/detail/'
    url = '{}{}'.format(nvd_url, cve)
    cve_obj.cve_nvd_url = url

    try:
        print(url)
        response = requests.get(url, headers=headers, timeout=60)
        # print(response.status_code)
        if response.status_code == 200:
            # fill description
            content = response.text
            description = re.findall('<p data-testid="vuln-description">(.*).</p>?', content)[0]
            print(description)
            cve_obj.cve_description = description

            severity = re.findall('"vuln-cvss3-panel-score">(.*)?</a>', content)
            score, cve_level, _ = severity[0].split(' ')
            cve_obj.cve_score = score
            cve_obj.cve_level = cve_level
            print(score, cve_level)
    except:
        print('v3 not scored, switch to v2...')
        try:
            soup = BeautifulSoup(content, "html.parser")
            score_level = soup.find('a',
                 id="p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_Cvss2CalculatorAnchor").get_text()
            score, cve_level = score_level.split(' ')
            cve_obj.cve_score = score
            cve_obj.cve_level = cve_level
            print(score, cve_level)
        except:
            cve_obj.cve_score = 'N/A'
            cve_obj.cve_level = 'N/A'
            print('v2 not scored either...')
    finally:
        cve_obj.show()
    pass


def write2html():
    """
    Write cve into to create a html file, this function is terriblely implemented, (^_^)
    :param keyword: software name
    :return: None
    """
    print('write data to html')
    html = ''
    header = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">\
            <html lang="en" xmlns="http://www.w3.org/1999/xhtml">\
<head>\
    <title>CVEs</title>\
    <meta content="text/html" charset="utf-8"></meta>\
    <link rel="stylesheet" type="text/css" href="list.css">\
    <style>body{background: #f5f5f5;margin:0px;margin-top:-20px;padding:0px;}#div_title{background:#2171c2;color: #fff;height: 60px;box-shadow:0 .25em .75em #CCC;padding-top:15px;margin-top:0px;font-family:"Microsoft Yahei" normal;font-size:12px;z-index: 20;    position: fixed;    width: 100%;}#div_title_inner{    width: 1004px;    margin-left: auto;    margin-right: auto;}#div_title h2{    width: 130px;display: inline-block;float: right;margin-top: 3.5%;}#div_title h1{font-weight: normal;    margin-left: auto;    margin-right: auto;    display: inline-block;    font-family: "Microsoft YaHei" !important;}#div_title_occupy{    height: 69px;}#div_main{width: 1004px;font-family: "Microsoft Yahei",helvetica,\'Lucida Grande\',Tahoma,Verdana,Simsun,Arial,Clean;margin-left: auto;margin-right: auto;    margin-top: 15px;}#div_content{    position: fixed;    width: 250px;    overflow-y:scroll; height:520px; overflow: auto;    background-color: #f2f2f2;    padding-left: 15px;    margin-top: 2px;}#div_content_body h3{    height: 10px;}#div_body{      width: 824px;    overflow: auto}#example_div{width: 650px;border: 1px dashed #cecfcf;background : #f5f6f7;font-family: Consolas,Menlo,"Liberation Mono",Courier,monospace!important;padding-left: 2px;padding-top: 5px;padding-bottom: 5px;font-size: 13px;min-height: 50px;}#uri_list_div a {    color: #5f940a;    text-decoration: none;    font-size: 13px;    height: 10px}#uri_list_div a:hover{    text-decoration: underline;}#data_style{    width:70px;}table.uri_t td{padding-left: 10px;    width: 550px;}table.t {    font-size: 13px;    margin-top: 5px;    margin-bottom: 5px;    width: 655px;    border: 1px solid #e4e4e4;    border-right: 0;    border-collapse: collapse;}table.t tr {    min-height: 25px;    line-height: 20px;}table.t th {    background-color: #efefef;    text-align: center;    border-right: 1px solid #e4e4e4;    border-bottom: 1px solid #e4e4e4;    color: #000;}table.t td {    border-right: 1px solid #e4e4e4;    border-bottom: 1px solid #e4e4e4;    color: #000;    background-color: #fff;    text-align: left;    padding-left: 5px;}#div_get, #div_post, #div_push{   background-color: #fff;   box-shadow: 0 2px 5px 0 rgba(0,0,0,.26);   padding: 64px;   margin: 2px 20px 20px 20px;}table.imagetable {font-family: verdana,arial,sans-serif;font-size:11px;color:#333333;border-width: 1px;border-color: #999999;border-collapse: collapse;}table.imagetable th {background:#b5cfd2 url(\'cell-blue.jpg\');border-width: 1px;padding: 8px;border-style: solid;border-color: #999999;}table.imagetable td {background:#dcddc0 url(\'cell-grey.jpg\');border-width: 1px;padding: 8px;border-style: solid;border-color: #999999;}</style>\
</head>\
<body>\
<div id="div_title_occupy"></div>'

    

    body = '<div id="div_main">\
    <div id="div_body">'
    body = '{}'.format(body)

    table = '<a name="vul-overview"></a><div id="div_get"> \
                <table class="uri_t" id="uri_table" border="1">\
                    <tr align="center">\
                        <td>等级</td>\
                        <td>严重</td>\
                        <td>高危</td>\
                        <td>中危</td>\
                        <td>低危</td>\
                        <td>N/A</td>\
                    </tr>\
                    <tr align="center">\
                        <td>个数({})</td>\
                        <td>{}</td>\
                        <td>{}</td>\
                        <td>{}</td>\
                        <td>{}</td>\
                        <td>{}</td>\
                    </tr>\
                </table>\
            </div>'

    a = b = c = d = e = 0
    for cve in cve_obj_list:
        if cve.cve_level == 'CRITICAL':
            a += 1
        elif cve.cve_level == 'HIGH':
            b += 1
        elif cve.cve_level == 'MEDIUM':
            c += 1
        elif cve.cve_level == 'LOW':
            d += 1
        else:
            e += 1

    table = table.format(cve_obj_list.__len__(), a, b, c, d, e)

    body = '{}{}'.format(body, table)

    for obj in cve_obj_list:
        cve_body = '<a name="{}"></a>\
            <div id="div_get">\
                <table class="uri_t" id="uri_table">\
                    <tr id="cve_no"><th>漏洞编号</th>\
                        <td>{}</td>\
                    </tr>\
                    <tr id="vul_level"><th>威胁评分</th>\
                        <td>{}</td>\
                    </tr>\
                    <tr id="cvss"><th>风险等级</th>\
                        <td>{}</td>\
                    </tr>\
                </table>\
                <p id="description">漏洞描述</p>\
                <div id="example_div"><a id="description">\
                    {}\
                    </a>\
                </div>\
                <p id="references">参考链接</p>\
                <div id="example_div"><a id="references" href="{}">{}</a>\
                    <br />\
                    </a>\
                </div>\
            </div>'

        cve_body = cve_body.format(obj.cve_no, obj.cve_no, obj.cve_score, obj.cve_level,
                                   obj.cve_description, obj.cve_nvd_url,obj.cve_nvd_url)

        body = '{}{}'.format(body, cve_body)

    footer = '</div>\
</div>\
<script>\
    function AjustContentHeight(){\
        var div_content = document.getElementById("div_content");\
        var div_body = document.getElementById("div_body")\
        var clientHeight = document.documentElement.clientHeight;\
        clientHeight -= 69;\
        div_content.style.height = clientHeight + "px";\
        div_body.style.height = clientHeight + "px";\
    }\
    window.onload=function(){AjustContentHeight();}\
    window.onresize=function(){AjustContentHeight();\
 }\
</script>\
</body>\
</html>'
    html = '{}{}{}'.format(header, body, footer)
    # write to cve html file for showing results
    file = 'cve-{}.html'.format(today)
    with open(file, 'w', encoding='utf-8') as fw:
        fw.write(html)
    return html
   # path = "php -f /var/www/html/wp-content/a_upload.php  /root/cve-everyday/{}".format(file)
  #  os.system(path)

def upload(html):
    #将数据直接传入wordpress数据库
    db = pymysql.connect("","","","")
    print(db)
    cursor = db.cursor()
    print(cursor)
    time = datetime.datetime.now()
    print(time)
    html=pymysql.escape_string(html)  
    title = '{}:CVE速览'.format(datetime.date.today())
    sql = """INSERT INTO `web`.`wp_posts`( `post_author`, `post_date`, `post_date_gmt`, `post_content`, `post_title`, `post_excerpt`, `post_status`, `comment_status`, `ping_status`, `post_password`, `post_name`, `to_ping`, `pinged`, `post_modified`, `post_modified_gmt`, `post_content_filtered`, `post_parent`, `guid`, `menu_order`, `post_type`, `post_mime_type`, `comment_count`) 
    VALUES ( 1, '{}', '{}', '{}', '{}', '{}', 'publish', 'open', 'closed', '', '{}', '', '', '{}', '{}', '', 0, '', 0, 'page', '', 0);""".format(time,time,html,title,title,title,time,time)
    sqla = """select * from wp_posts"""
    print(sql)
    try:
        cursor.execute(sql)
        db.commit()
    except:
        db.rollback()
    db.close()

if __name__ == '__main__':

    # 获取每日更新的漏洞URL
    cve_url_list = get_cve_urls()

    # 分离URL中的CVE编号，使用NVD查询漏洞的详细信息
    total = len(cve_url_list)
    index = 0
    for line in cve_url_list:
        index += 1
        _, num = line.split('name=')
        cve_no = 'CVE-{}'.format(num)
        msg = '[{}/{}]CVE-{}'.format(index, total, num)
        print(msg)
        cve_obj = CveObject()
        fill_with_nvd(cve_no, cve_obj)
        cve_obj_list.append(cve_obj)
    html=write2html()
    upload(html)


    
    pass
