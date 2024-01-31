import subprocess
import requests
import re
import nltk
from bs4 import BeautifulSoup
import whois
import language_tool_python
import concurrent.futures
import logging

# Download NLTK resources
nltk.download('wordnet')

# Set up logging
logging.basicConfig(filename='website_analysis.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def clone_repositories():
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            sqlmap_future = executor.submit(subprocess.run, ['git', 'clone', 'https://github.com/sqlmapproject/sqlmap.git'], capture_output=True, text=True)
            nmap_future = executor.submit(subprocess.run, ['git', 'clone', 'https://github.com/nmap/nmap.git'], capture_output=True, text=True)
            sqlmap_output = sqlmap_future.result().stdout
            nmap_output = nmap_future.result().stdout
        return sqlmap_output, nmap_output
    except Exception as e:
        logging.error(f"Error cloning repositories: {e}")
        return "", ""

def fetch_html_content(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching HTML content from {url}: {e}")
        return None

def parse_html(html_content):
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        title = soup.title.text.strip()
        meta_tags = soup.find_all('meta')
        headers = {tag.name: len(soup.find_all(tag.name)) for tag in soup.find_all(re.compile(r'h[1-6]'))}  # Extract header tags (h1 to h6)
        text = soup.get_text().strip()
        return title, meta_tags, headers, text
    except Exception as e:
        logging.error(f"Error parsing HTML content: {e}")
        return "", [], {}, ""

def analyze_meta_title(meta_title):
    try:
        if meta_title:
            length_score = min(100, len(meta_title) * 2)  # Longer titles get a higher score
            return length_score
        else:
            return 0
    except Exception as e:
        logging.error(f"Error analyzing meta title: {e}")
        return 0

def generate_synonyms(word):
    try:
        synonyms = set()
        for synset in nltk.corpus.wordnet.synsets(word):
            for lemma in synset.lemmas():
                synonyms.add(lemma.name())
        return list(synonyms)
    except Exception as e:
        logging.error(f"Error generating synonyms: {e}")
        return []

def modify_seo_with_similar_words(seo_report):
    try:
        modified_seo_report = {}
        for key, value in seo_report.items():
            if isinstance(value, str):
                modified_value = ' '.join(generate_synonyms(word) for word in value.split())
                modified_seo_report[key] = modified_value
            else:
                modified_seo_report[key] = value
        return modified_seo_report
    except Exception as e:
        logging.error(f"Error modifying SEO report with similar words: {e}")
        return seo_report

def check_security_vulnerabilities(html_content):
    try:
        vulnerabilities = []
        if re.search(r'<script', html_content):
            vulnerabilities.append('Script tag found')
        if re.search(r'<iframe', html_content):
            vulnerabilities.append('iFrame tag found')
        return vulnerabilities
    except Exception as e:
        logging.error(f"Error checking security vulnerabilities: {e}")
        return []

def analyze_seo(title, meta_tags, headers, text, html_content, url):
    try:
        seo_score = 0
        seo_score += analyze_meta_title(title)
        return seo_score
    except Exception as e:
        logging.error(f"Error analyzing SEO: {e}")
        return 0

def check_seo_compliance(seo_score):
    try:
        if seo_score >= 90:
            return "White-hat SEO"
        elif seo_score >= 70:
            return "Gray-hat SEO"
        else:
            return "Black-hat SEO"
    except Exception as e:
        logging.error(f"Error determining SEO compliance: {e}")
        return "Unknown"

def get_domain_info(url):
    try:
        domain = whois.whois(url)
        return str(domain)
    except Exception as e:
        logging.error(f"Error retrieving domain information: {e}")
        return ""

def check_website_pages(html_content):
    try:
        pages = {
            "Terms and Conditions": False,
            "Contact Us": False,
            "FAQ": False
        }
        if re.search(r'terms\s+and\s+conditions', html_content, re.IGNORECASE):
            pages["Terms and Conditions"] = True
        if re.search(r'contact\s+us', html_content, re.IGNORECASE):
            pages["Contact Us"] = True
        if re.search(r'faq', html_content, re.IGNORECASE):
            pages["FAQ"] = True
        return pages
    except Exception as e:
        logging.error(f"Error checking website pages: {e}")
        return {}

def check_backlinks(html_content):
    try:
        backlinks = []
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a', href=True):
            backlinks.append(link['href'])
        return backlinks
    except Exception as e:
        logging.error(f"Error checking backlinks: {e}")
        return []

def check_language_errors(text):
    try:
        tool = language_tool_python.LanguageTool('en-US')
        matches = tool.check(text)
        return [match.msg for match in matches]
    except Exception as e:
        logging.error(f"Error checking language errors: {e}")
        return []

def generate_report(url, title, meta_tags, headers, seo_report, vulnerabilities, domain_info, website_pages, backlinks, language_errors):
    try:
        report = f"Report for {url}\n"
        report += f"Title: {title}\n"
        report += "Meta Tags:\n"
        for tag in meta_tags:
            report += f"\t{tag.get('name', '')}: {tag.get('content', '')}\n"
        report += "Headers:\n"
        for header, count in headers.items():
            report += f"\t{header}: {count}\n"
        report += "\nSEO Analysis:\n"
        seo_score = seo_report['SEO Score']
        report += f"SEO Score: {seo_score}\n"
        report += f"SEO Compliance: {check_seo_compliance(seo_score)}\n"
        report += "\nSecurity Vulnerabilities:\n"
        if vulnerabilities:
            report += "\n".join(vulnerabilities)
        else:
            report += "No security vulnerabilities found"
        report += "\n\nDomain Information:\n"
        report += domain_info
        report += "\n\nWebsite Pages:\n"
        for page, present in website_pages.items():
            report += f"{page}: {'Yes' if present else 'No'}\n"
        report += "\nBacklinks:\n"
        if backlinks:
            report += "\n".join(backlinks)
        else:
            report += "No backlinks found"
        report += "\n\nLanguage Errors:\n"
        if language_errors:
            report += "\n".join(language_errors)
        else:
            report += "No language errors found"
        return report
    except Exception as e:
        logging.error(f"Error generating report: {e}")
        return ""

def main():
    try:
        # Clone repositories
        logging.info("Cloning repositories...")
        sqlmap_output, nmap_output = clone_repositories()
        logging.info("SQLMap Output:")
        logging.info(sqlmap_output)
        logging.info("\nNmap Output:")
        logging.info(nmap_output)

        # Prompt user for the URL of the webpage
        url = input("Enter the URL of the website: ")
        # Fetch HTML content of the webpage
        html_content = fetch_html_content(url)
        if html_content:
            # Parse HTML content to extract relevant information
            title, meta_tags, headers, text = parse_html(html_content)
            if title is None:
                print("Failed to parse HTML content. Check the URL and try again.")
                logging.error("Failed to parse HTML content")
                return
            # Analyze SEO performance of the webpage
            seo_score = analyze_seo(title, meta_tags, headers, text, html_content, url)
            # Generate SEO report with modified SEO words
            seo_report = {'SEO Score': seo_score}
            modified_seo_report = modify_seo_with_similar_words(seo_report)
            # Check for security vulnerabilities
            vulnerabilities = check_security_vulnerabilities(html_content)
            # Get domain information
            domain_info = get_domain_info(url)
            # Check for website pages such as Terms and Conditions, Contact Us, FAQ, etc.
            website_pages = check_website_pages(html_content)
            # Check for backlinks
            backlinks = check_backlinks(html_content)
            # Check for language errors
            language_errors = check_language_errors(text)
            # Generate comprehensive report
            report = generate_report(url, title, meta_tags, headers, modified_seo_report, vulnerabilities, domain_info, website_pages, backlinks, language_errors)
            print(report)
        else:
            print("Failed to fetch HTML content. Check the URL and try again.")
    except Exception as e:
        logging.error(f"Error in main function: {e}")
        print("An error occurred. Please check the log file for details.")

if __name__ == "__main__":
    main()
