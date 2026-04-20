#!/usr/bin/env python3

"""
linkedin2username by initstring (github.com/initstring)

OSINT tool to discover likely usernames and email addresses for employees
of a given company on LinkedIn. This tool actually logs in with your valid
account in order to extract the most results.

Modified to support --alphablast and --fullblast to bypass the 1,000 record limit.
"""

import os
import sys
import re
import time
import argparse
import json
import urllib.parse
import requests
import urllib3

from selenium import webdriver
from selenium.common.exceptions import WebDriverException

BANNER = r"""

                            .__  .__________
                            |  | |__\_____  \ __ __
                            |  | |  |/  ____/|  |  \
                            |  |_|  /       \|  |  /
                            |____/__\_______ \____/
                               linkedin2username

                                   Spray away.
                              github.com/initstring

"""

GEO_REGIONS = {
    "ar": "100446943",
    "at": "103883259",
    "au": "101452733",
    "be": "100565514",
    "bg": "105333783",
    "ca": "101174742",
    "ch": "106693272",
    "cl": "104621616",
    "de": "101282230",
    "dk": "104514075",
    "es": "105646813",
    "fi": "100456013",
    "fo": "104630756",
    "fr": "105015875",
    "gb": "101165590",
    "gf": "105001561",
    "gp": "104232339",
    "gr": "104677530",
    "gu": "107006862",
    "hr": "104688944",
    "hu": "100288700",
    "is": "105238872",
    "it": "103350119",
    "li": "100878084",
    "lu": "104042105",
    "mq": "103091690",
    "nl": "102890719",
    "no": "103819153",
    "nz": "105490917",
    "pe": "102927786",
    "pl": "105072130",
    "pr": "105245958",
    "pt": "100364837",
    "py": "104065273",
    "re": "104265812",
    "rs": "101855366",
    "ru": "101728296",
    "se": "105117694",
    "sg": "102454443",
    "si": "106137034",
    "tw": "104187078",
    "ua": "102264497",
    "us": "103644278",
    "uy": "100867946",
    "ve": "101490751"
}

ALPHABET = list('abcdefghijklmnopqrstuvwxyz')


class NameMutator():
    """
    This class handles all name mutations.
    Init with a raw name, and then call the individual functions to return a mutation.
    """
    def __init__(self, name):
        self.name = self.clean_name(name)
        self.name = self.split_name(self.name)

    @staticmethod
    def clean_name(name):
        name = name.lower()
        name = re.sub("[àáâãäå]", 'a', name)
        name = re.sub("[èéêë]", 'e', name)
        name = re.sub("[ìíîï]", 'i', name)
        name = re.sub("[òóôõö]", 'o', name)
        name = re.sub("[ùúûü]", 'u', name)
        name = re.sub("[ýÿ]", 'y', name)
        name = re.sub("[ß]", 'ss', name)
        name = re.sub("[ñ]", 'n', name)
        name = re.sub(r'\([^()]*\)', '', name)
        allowed_chars = re.compile('[^a-zA-Z -]')
        name = allowed_chars.sub('', name)
        titles = ['mr', 'miss', 'mrs', 'phd', 'prof', 'professor', 'md', 'dr', 'mba']
        pattern = "\\b(" + "|".join(titles) + ")\\b"
        name = re.sub(pattern, '', name)
        name = re.sub(r'\s+', ' ', name).strip()
        return name

    @staticmethod
    def split_name(name):
        parsed = re.split(r'[\s-]+', name)
        parsed = [part for part in parsed if part]
        if len(parsed) < 2:
            return None
        if len(parsed) > 2:
            split_name = {'first': parsed[0], 'second': parsed[-2], 'last': parsed[-1]}
        else:
            split_name = {'first': parsed[0], 'second': '', 'last': parsed[-1]}
        if not split_name['first'] or not split_name['last']:
            return None
        return split_name

    def f_last(self):
        names = set()
        names.add(self.name['first'][0] + self.name['last'])
        if self.name['second']:
            names.add(self.name['first'][0] + self.name['second'])
        return names

    def f_dot_last(self):
        names = set()
        names.add(self.name['first'][0] + '.' + self.name['last'])
        if self.name['second']:
            names.add(self.name['first'][0] + '.' + self.name['second'])
        return names

    def last_f(self):
        names = set()
        names.add(self.name['last'] + self.name['first'][0])
        if self.name['second']:
            names.add(self.name['second'] + self.name['first'][0])
        return names

    def first_dot_last(self):
        names = set()
        names.add(self.name['first'] + '.' + self.name['last'])
        if self.name['second']:
            names.add(self.name['first'] + '.' + self.name['second'])
        return names

    def first_l(self):
        names = set()
        names.add(self.name['first'] + self.name['last'][0])
        if self.name['second']:
            names.add(self.name['first'] + self.name['second'][0])
        return names

    def first(self):
        names = set()
        names.add(self.name['first'])
        return names


def parse_arguments():
    desc = ('OSINT tool to generate lists of probable usernames from a'
            ' given company\'s LinkedIn page.')
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument('-c', '--company', type=str, action='store', required=True,
                        help='Company name exactly as typed in the LinkedIn URL.')
    parser.add_argument('-n', '--domain', type=str, action='store', default='',
                        help='Append a domain name to username output. '
                             '[example: "-n uber.com" -> jschmoe@uber.com]')
    parser.add_argument('-d', '--depth', type=int, action='store', default=False,
                        help='Search depth (pages of 50). Defaults to auto.')
    parser.add_argument('-s', '--sleep', type=int, action='store', default=0,
                        help='Seconds to sleep between requests. Defaults to 0.')
    parser.add_argument('-x', '--proxy', type=str, action='store', default=False,
                        help='Proxy server. WARNING: disables SSL verification. '
                             '[example: "-x https://localhost:8080"]')
    parser.add_argument('-k', '--keywords', type=str, action='store', default=False,
                        help='Comma-separated keywords to filter results. '
                             '[example: "-k sales,engineering"]')
    parser.add_argument('-g', '--geoblast', default=False, action="store_true",
                        help='Bypass the 1,000 limit by searching across geographic regions.')
    parser.add_argument('-a', '--alphablast', default=False, action="store_true",
                        help='Bypass the 1,000 limit by searching letters a-z (~26,000 max).')
    parser.add_argument('-f', '--fullblast', default=False, action="store_true",
                        help='Maximum coverage: all regions x all letters. Use --sleep to '
                             'avoid rate limiting. Empty regions are auto-skipped.')
    parser.add_argument('-o', '--output', default="li2u-output", action="store",
                        help='Output directory. Defaults to li2u-output.')

    args = parser.parse_args()

    args.proxy_dict = {"https": args.proxy}

    if args.domain:
        args.domain = '@' + args.domain

    if args.keywords:
        args.keywords = args.keywords.split(',')

    active_modes = sum([bool(args.keywords), args.geoblast, args.alphablast, args.fullblast])
    if active_modes > 1:
        print("[!] Please use only one of: --keywords, --geoblast, --alphablast, --fullblast.")
        sys.exit()

    return args


def get_webdriver():
    for browser in [webdriver.Firefox, webdriver.Chrome]:
        try:
            return browser()
        except WebDriverException:
            continue
    return None


def login():
    driver = get_webdriver()
    if driver is None:
        print("[!] Could not find a supported browser for Selenium. Exiting.")
        sys.exit(1)

    driver.get("https://linkedin.com/login")
    print("[*] Log in to LinkedIn. Leave the browser open and press enter when ready...")
    input("Ready? Press Enter!")

    selenium_cookies = driver.get_cookies()
    driver.quit()

    session = requests.Session()
    for cookie in selenium_cookies:
        session.cookies.set(cookie['name'], cookie['value'])

    mobile_agent = ('Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; SCH-I535 '
                    'Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) '
                    'Version/4.0 Mobile Safari/534.30')
    session.headers.update({'User-Agent': mobile_agent,
                            'X-RestLi-Protocol-Version': '2.0.0',
                            'X-Li-Track': '{"clientVersion":"1.13.1665"}'})
    session = set_csrf_token(session)
    return session


def set_csrf_token(session):
    csrf_token = session.cookies['JSESSIONID'].replace('"', '')
    session.headers.update({'Csrf-Token': csrf_token})
    return session


def get_company_info(name, session):
    escaped_name = urllib.parse.quote_plus(name)
    response = session.get('https://www.linkedin.com'
                           '/voyager/api/organization/companies?'
                           'q=universalName&universalName=' + escaped_name)

    if response.status_code == 404:
        print("[!] Could not find that company name. Please double-check LinkedIn and try again.")
        sys.exit()
    if response.status_code != 200:
        print(f"[!] Unexpected HTTP {response.status_code} when getting company info.")
        sys.exit()
    if 'mwlite' in response.text:
        print("[!] You are being served the 'lite' LinkedIn version, not supported here.")
        sys.exit()

    try:
        response_json = json.loads(response.text)
    except json.decoder.JSONDecodeError:
        print("[!] Could not decode JSON when getting company info!")
        print(response.text[:200])
        sys.exit()

    company = response_json["elements"][0]
    found_name    = company.get('name', "NOT FOUND")
    found_desc    = company.get('tagline', "NOT FOUND")
    found_staff   = company['staffCount']
    found_website = company.get('companyPageUrl', "NOT FOUND")
    found_id      = company['trackingInfo']['objectUrn'].split(':')[-1]

    print("          Name:  " + found_name)
    print("          ID:    " + found_id)
    print("          Desc:  " + found_desc)
    print("          Staff: " + str(found_staff))
    print("          URL:   " + found_website)
    print(f"\n[*] Hopefully that's the right {name}! If not, check LinkedIn and try again.\n")

    return (found_id, found_staff)


def set_outer_loops(args):
    """
    Returns a list of (region_id, keyword) tuples covering all planned searches.
    """
    if args.fullblast:
        outer_loops = [
            (region_id, letter)
            for _, region_id in GEO_REGIONS.items()
            for letter in ALPHABET
        ]
        print(f"[*] Fullblast mode: {len(outer_loops)} combinations "
              f"({len(GEO_REGIONS)} regions x {len(ALPHABET)} letters). "
              f"Empty regions will be auto-skipped.")
    elif args.geoblast:
        outer_loops = [(region_id, '') for _, region_id in GEO_REGIONS.items()]
        print(f"[*] Geoblast mode: {len(outer_loops)} geographic regions.")
    elif args.alphablast:
        outer_loops = [('', letter) for letter in ALPHABET]
        print(f"[*] Alphablast mode: {len(outer_loops)} alphabet searches.")
    elif args.keywords:
        outer_loops = [('', kw) for kw in args.keywords]
        print(f"[*] Keyword mode: {len(outer_loops)} keyword(s).")
    else:
        outer_loops = [('', '')]

    return outer_loops


def set_inner_loops(staff_count, args):
    """
    Defines pages of 50 to fetch per outer loop. Hard-capped at 20 (LinkedIn's limit of 1000).
    """
    max_pages_per_search = 20
    loops = min(int((staff_count / 50) + 1), max_pages_per_search)

    print(f"[*] Company has {staff_count} profiles to check. Some may be anonymous.")

    if staff_count > 1000:
        if not any([args.geoblast, args.alphablast, args.fullblast, args.keywords]):
            print("[!] LinkedIn limits results to 1,000 per search.\n"
                  "    Try --alphablast, --geoblast, or --fullblast to get more.")
        elif args.fullblast:
            print("[*] Fullblast enabled — maximum coverage across all regions and letters.")
        elif args.geoblast:
            print("[*] Geoblast enabled — searching across geographic regions.")
        elif args.alphablast:
            print("[*] Alphablast enabled — searching across alphabet letters.")
    elif staff_count < 1000 and args.geoblast:
        print("[!] Geoblast not necessary for this company size. Disabling.")
        args.geoblast = False

    if args.depth and args.depth < loops:
        print(f"[!] Custom depth {args.depth} is lower than computed {loops}.\n")
    else:
        print(f"[*] Each iteration: up to {loops} pages of 50 results.\n")
        args.depth = loops

    return args.depth


def get_results(session, company_id, page, region, keyword):
    """Fetches one page of search results from the LinkedIn Voyager API."""
    url = ('https://www.linkedin.com/voyager/api/graphql?variables=('
           f'start:{page * 50},'
           f'query:('
           f'{f"keywords:{keyword}," if keyword else ""}'
           'flagshipSearchIntent:SEARCH_SRP,'
           f'queryParameters:List((key:currentCompany,value:List({company_id})),'
           f'{f"(key:geoUrn,value:List({region}))," if region else ""}'
           '(key:resultType,value:List(PEOPLE))'
           '),'
           'includeFiltersInResponse:false'
           '),count:50)'
           '&queryId=voyagerSearchDashClusters.66adc6056cf4138949ca5dcb31bb1749')

    return session.get(url)


def find_employees(result):
    """
    Parses a raw HTTP response body and returns a list of employee dicts.
    Returns False on JSON error or when no results are found.

    Defensive against None values anywhere in the JSON tree (LinkedIn sometimes
    returns null for searchDashClustersByAll when a region/keyword has no results).
    """
    try:
        result_json = json.loads(result)
    except json.decoder.JSONDecodeError:
        print("\n[!] Could not decode JSON when scraping this loop!")
        print(result[:200])
        return False

    # Use 'or {}' / 'or []' guards so that explicit JSON null values
    # (parsed as Python None) don't cause AttributeError on .get()
    data            = result_json.get('data') or {}
    search_clusters = data.get('searchDashClustersByAll') or {}
    elements        = search_clusters.get('elements') or []
    paging          = search_clusters.get('paging') or {}
    total           = paging.get('total', 0)

    if not search_clusters or total == 0:
        return False

    found_employees = []
    for element in elements:
        for item_body in element.get('items') or []:
            entity = (item_body.get('item') or {}).get('entityResult') or {}

            if not entity:
                continue

            full_name = entity['title']['text'].strip()
            if full_name[:3] == 'Dr ':
                full_name = full_name[4:]

            occupation = ((entity.get('primarySubtitle') or {}).get('text') or '')

            found_employees.append({'full_name': full_name, 'occupation': occupation})

    return found_employees or False


def do_loops(session, company_id, outer_loops, args):
    """
    Runs all HTTP scraping loops with deduplication and empty-region skipping.

    outer_loops: list of (region_id, keyword) tuples.
    In fullblast mode, if a region's first page returns no results the region
    is marked empty and all remaining letter variants for it are skipped,
    saving up to 25 unnecessary requests per empty region.
    """
    employee_list = []
    seen          = set()   # (full_name, occupation) — dedup across ALL loops
    empty_regions = set()   # region_ids confirmed to have 0 results
    total_requests = 0

    try:
        for loop_index, (current_region, current_keyword) in enumerate(outer_loops):

            # Fullblast optimisation: skip regions already confirmed empty
            if args.fullblast and current_region and current_region in empty_regions:
                continue

            # Progress header
            if len(outer_loops) > 1:
                label_parts = []
                if current_region:
                    region_name = next(
                        (k for k, v in GEO_REGIONS.items() if v == current_region),
                        current_region
                    )
                    label_parts.append(f"region={region_name}")
                if current_keyword:
                    label_parts.append(f"keyword='{current_keyword}'")
                label = ", ".join(label_parts) if label_parts else "default"
                print(f"\n[*] Outer loop {loop_index + 1}/{len(outer_loops)}: {label}")

            # Inner loop: pages of 50
            for page in range(0, args.depth):
                new_names = 0
                sys.stdout.flush()
                sys.stdout.write(f"[*] Scraping page {page + 1}...    ")

                result = get_results(session, company_id, page, current_region, current_keyword)
                total_requests += 1

                if result.status_code != 200:
                    print(f"\n[!] HTTP {result.status_code} — bailing from this loop.")
                    break

                if "UPSELL_LIMIT" in result.text:
                    sys.stdout.write('\n')
                    print("[!] Commercial search limit hit! Try again on the 1st of the month.")
                    break

                found_employees = find_employees(result.text)

                if not found_employees:
                    sys.stdout.write('\n')
                    if args.fullblast and current_region and page == 0:
                        empty_regions.add(current_region)
                        print("[*] Region has no results — skipping remaining letters for it.")
                    else:
                        print("[*] No more results — moving to next loop.")
                    break

                # Deduplicate before appending
                for emp in found_employees:
                    key = (emp['full_name'], emp['occupation'])
                    if key not in seen:
                        seen.add(key)
                        employee_list.append(emp)
                        new_names += 1

                sys.stdout.write(
                    f"    [+] {new_names} new unique names. "
                    f"Total unique: {len(employee_list)} "
                    f"(requests: {total_requests}, empty regions skipped: {len(empty_regions)})"
                    "              \r"
                )

                if args.sleep:
                    time.sleep(args.sleep)

    except KeyboardInterrupt:
        print("\n\n[!] Caught Ctrl-C. Breaking loops and writing files.")

    print(f"\n\n[*] Done. Unique employees: {len(employee_list)} | "
          f"Requests: {total_requests} | "
          f"Empty regions skipped: {len(empty_regions)}")

    return employee_list


def write_lines(employees, name_func, domain, outfile):
    for employee in employees:
        mutator = NameMutator(employee["full_name"])
        if mutator.name:
            for name in getattr(mutator, name_func)():
                outfile.write(name + domain + '\n')


def write_files(company, domain, employees, out_dir):
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)

    with open(f'{out_dir}/{company}-rawnames.txt', 'w', encoding='utf-8') as f:
        for emp in employees:
            f.write(emp['full_name'] + '\n')

    with open(f'{out_dir}/{company}-metadata.txt', 'w', encoding='utf-8') as f:
        f.write('full_name,occupation\n')
        for emp in employees:
            f.write(emp['full_name'] + ',' + emp["occupation"] + '\n')

    for fname, method in [
        ('flast',      'f_last'),
        ('f.last',     'f_dot_last'),
        ('firstl',     'first_l'),
        ('first.last', 'first_dot_last'),
        ('first',      'first'),
        ('lastf',      'last_f'),
    ]:
        with open(f'{out_dir}/{company}-{fname}.txt', 'w', encoding='utf-8') as f:
            write_lines(employees, method, domain, f)

    print(f"[*] Files written to: {out_dir}/")


def main():
    print(BANNER + "\n\n\n")
    args = parse_arguments()

    session = login()
    if not session:
        sys.exit()

    if args.proxy:
        print("[!] Using a proxy — SSL verification disabled.")
        session.verify = False
        urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)
        session.proxies.update(args.proxy_dict)

    print("[*] Trying to get company info...")
    company_id, staff_count = get_company_info(args.company, session)

    print("[*] Calculating search plan...")
    args.depth = set_inner_loops(staff_count, args)
    outer_loops = set_outer_loops(args)

    print("[*] Starting search.... Press Ctrl-C to break and write files early.\n")
    employees = do_loops(session, company_id, outer_loops, args)

    write_files(args.company, args.domain, employees, args.output)
    print(f"\n[*] All done! Check out your files in {args.output}")


if __name__ == "__main__":
    main()

