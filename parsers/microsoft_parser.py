import shutil
import pprint
import requests
import json
from openpyxl import load_workbook
import logging
import bs4
from functions import *
import re
import os
import progressbar

__author__ = 'Aleksei Shcherbakov'
__version__ = '0.02'

PROXIES = dict()

# Настройка логера
logging.basicConfig(format=u'%(levelname)-8s [%(asctime)s] %(message)s', level=logging.DEBUG, filename=u'log.log')

# Парсинг security_guidance, появился только в 2017г.
# TODO: Сделано только получение всех уязвимостей через API в формате JSON
def parse_security_guidance():
    url = 'https://portal.msrc.microsoft.com/api/security-guidance/en-us'

    # Конфигурация для фильтрации будет передаваться в формате JSON
    headers = {'Content-Type': 'application/json;charset=utf-8'}

    # Фильтрация информации об уязвимостях
    data = '{"familyIds":'\
           '[100000000,100000001,100000002,100000003,100000004,100000005,100000006,100000007,5000,100000008, ' \
           '100000009,100000010],' \
           '"productIds":[],' \
           '"severityIds":[],' \
           '"impactIds":[],' \
           '"pageNumber":1,' \
           '"pageSize":100000,' \
           '"includeCveNumber":true,' \
           '"includeSeverity":true,' \
           '"includeImpact":true,' \
           '"includeMonthly":true,' \
           '"orderBy":"publishedDate",' \
           '"orderByMonthly":' \
           '"releaseDate",' \
           '"isDescending":true,' \
           '"isDescendingMonthly":true,' \
           '"queryText":"",' \
           '"isSearch":false,' \
           '"filterText":"",' \
           '"fromPublishedDate":"01/01/1998",' \
           '"toPublishedDate":"05/27/2017"}'

    req = requests.post(url, headers=headers, data=data)
    # Ответ передается в формате JSON сразу парсим его
    data = req.json()
    with open('test_ans.json', 'w') as file:
        file.write(json.dumps(data, indent=2))
        pp = pprint.PrettyPrinter(indent=4)
        # pp.pprint(data)

        print(data['count'])

    return None


# Cкачиваем файл BulletinSearch.xlsx содержащий информацию о бюллютенях безопасности после 2008г.
def get_BulletinSearch_new(proxy):
    if not os.path.exists('BulletinSearch.xlsx'):
        url = 'https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx'
        req = requests.get(url, proxies=PROXIES, stream=True)
        with open('BulletinSearch.xlsx', 'wb') as file_handler:
            shutil.copyfileobj(req.raw, file_handler)


# Парсинг архива уязвимостей 2008г.-2017г.
def parse_ms_bulletin_new_xlsx(year, num):
    # Парсим xlsx файл
    # Столбцы:
    # 0 - Date Posted
    # 1 - Bulletin Id
    # 2 - Bulletin KB
    # 3 - Severity
    # 4 - Impact
    # 5 - Title
    # 6 - Affected Product
    # 7 - Component KB
    # 8 - Affected Component
    # 9 - Impact
    # 10 - Severity
    # 11 - Supersedes (?)
    # 12 - Reboot (?)
    # 13 - CVEs

    wb = load_workbook(filename='BulletinSearch.xlsx', read_only=True)
    ws = wb.active

    vulner = dict()
    vulners = list()

    prev_id = None
    data_is_none = True

    bar = progressbar.ProgressBar(max_value=progressbar.UnknownLength)

    for number, row in enumerate(ws.rows):

        # Фильтруем названия столбцов и пустые строки
        if row[0].value == 'Date Posted' or row[0].value is None:
            continue

        # Пропускаем те уязвимости, которые уже есть в базе уязвимостей
        cur_year, cur_num = map(int, re.search('\d+-\d+', row[1].value).group(0).split('-'))
        if (cur_year < year) or (cur_year == year and cur_num <= num):
            continue
        else:
            data_is_none = False

        # Если id не совпадает с предыдущей уязвимостью, то обрабатываем ее
        if row[1].value != prev_id:
            # Выписываем информацию, которую можно получить из эксель файла
            # Получение общих сведений об обновлении безопасности, помещаются в словарь vulner
            # Impact - оценка воздействия, возможные значения: Low, Medium, High, Critical
            # Description - описание типа уязвимости
            # Announced - дата выхода обновления
            # Products - продукты для которых актуальна уязвимость
            # name - название уязвимости
            # id - id обновления безопасности от MS
            # url - ссылка на описание бюллютеня безопаспасноти
            # Affected component - уязвимый компонент, может быть не указан
            # СVE - CVE id, соответствующие этому бюллютеню
            # References - источники, связанные с уязвимостью
            if vulner:
                yield vulner

            vulner['Products'] = list()
            prev_id = row[1].value
            vulner['Announced'] = row[0].value.strftime('%d.%m.%Y')
            vulner['url'] = 'https://technet.microsoft.com/library/security/{}'.format(row[1].value)
            vulner['id'] = row[1].value
            vulner['Impact'] = row[3].value
            vulner['Description'] = row[4].value
            vulner['name'] = row[5].value
            vulner['Products'].append(row[6].value)
            if row[8].value is not None:
                vulner['Affected component'] = row[8].value
            vulner['CVE'] = row[13].value
            vulner['Workaround'] = 'Install Microsoft security update {}, more instructions at {}'.format(
                row[2].value,
                'https://support.microsoft.com/kb/{}'.format(row[2].value))
            vulner['References'] = [vulner['url'], ]

            # TODO: Парсим дополнительную информацию с сайта
            # parse_msb_new_url(vulner)

            bar.update(number)

            yield vulner

        # Если совпадает, то добавляем новый продукт к последней уязвимости
        else:
            vulner['Products'].append(row[6].value)
    if data_is_none:
        logging.info('База уязвимостей в актуальном состоянии')
        print('База уязвимостей в актуальном состоянии')

# TODO: Не работает
def parse_msb_new_url(vulner):
#    logging.debug('Начинается парсинг следующего URL:{}'.format(vulner['url']))
    html_str = requests.get(vulner['url']).content
    soup = bs4.BeautifulSoup(html_str, 'html.parser')
    # То за что можно зацепиться при парсинге - навигационная панель
    # Получим id внутренних ссылок для важной информации
    nav_info = dict()
    nav_bar = soup.select('div.Nav_Sidebar')
    a_nav_bar = nav_bar[0].select('a')
    for anchor in a_nav_bar:
        if 'Vulnerability Information' in anchor.contents[0]:
            nav_info['vuln_info'] = anchor.get('href').lstrip('#')
        if 'Workarounds' in anchor.contents[0]:
            nav_info['Workarounds'] = anchor.get('href').lstrip('#')

    print(nav_info)
    for name, id in nav_info.items():
        print(name)
        tag = soup.find(id=id)
        # Выбираем якорь на подзаголовок, он стоит перед текстом
        a = tag.find_next('a').find_next('a').find_next('a')
        p_tags = a.find_next_siblings('p')
        for tag in p_tags:
            for content in tag.contents:
                if isinstance(content, str):
                    print(content, end='')
                else:
                    print(content.contents[0], end='')
            print()

 #       a = tag.select('div.sectionblock')
        # Выбираем
       # print(a)
        #  print(a.next_sibling.next_sibling.next_sibling.next_sibling)


# TODO: Сделать
def get_BulletinSearch(proxy):
    pass


# TODO: Сделать
def parse_ms_bulletin_xlsx(year, num):
    pass


def run_ms_parsing(proxy, output_path, year, num):

    if proxy is not None:
        PROXIES['http'] = proxy
        PROXIES['https'] = proxy

    get_BulletinSearch_new(proxy)
    data = parse_ms_bulletin_new_xlsx(year, num)
    vuln_crawler.to_xml(output_path, data)

