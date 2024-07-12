import streamlit as st
import joblib
import json
import numpy as np
from urllib.parse import urlparse
from tld import get_tld
import re

lgb = joblib.load('lgb_model.pkl')
lb_make = joblib.load('label_encoder.pkl')

with open('feature_columns.json') as f:
    feature_columns = json.load(f)


def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    return 1 if match else 0


def abnormal_url(url):
    hostname = urlparse(url).hostname
    match = re.search(str(hostname), url)
    return 1 if match else 0


def count_dot(url):
    return url.count('.')


def count_www(url):
    return url.count('www')


def count_atrate(url):
    return url.count('@')


def no_of_dir(url):
    return urlparse(url).path.count('/')


def no_of_embed(url):
    return urlparse(url).path.count('//')


def shortening_service(url):
    match = re.search(
        'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|yfrog\.com|'
        'migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|'
        'ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|'
        'wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|cur\.lv|tinyurl\.com|'
        'ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|'
        'prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|'
        'link\.zip\.net', url)
    return 1 if match else 0


def count_https(url):
    return url.count('https')


def count_http(url):
    return url.count('http')


def count_per(url):
    return url.count('%')


def count_ques(url):
    return url.count('?')


def count_hyphen(url):
    return url.count('-')


def count_equal(url):
    return url.count('=')


def url_length(url):
    return len(str(url))


def hostname_length(url):
    return len(urlparse(url).netloc)


def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr', url)
    return 1 if match else 0


def digit_count(url):
    return sum(1 for i in url if i.isnumeric())


def letter_count(url):
    return sum(1 for i in url if i.isalpha())


def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except IndexError:
        return 0


def tld_length(tld):
    try:
        return len(tld)
    except TypeError:
        return -1


def extract_features(url):
    features = []
    features.append(having_ip_address(url))
    features.append(abnormal_url(url))
    features.append(count_dot(url))
    features.append(count_www(url))
    features.append(count_atrate(url))
    features.append(no_of_dir(url))
    features.append(no_of_embed(url))
    features.append(shortening_service(url))
    features.append(count_https(url))
    features.append(count_http(url))
    features.append(count_per(url))
    features.append(count_ques(url))
    features.append(count_hyphen(url))
    features.append(count_equal(url))
    features.append(url_length(url))
    features.append(hostname_length(url))
    features.append(suspicious_words(url))
    features.append(digit_count(url))
    features.append(letter_count(url))
    features.append(fd_length(url))
    tld = get_tld(url, fail_silently=True)
    features.append(tld_length(tld))
    return np.array(features).reshape((1, -1))


st.title("SAFE WEB")
url = st.text_input("Enter a domain to check if it's safe or not:")

if st.button("Check Domain"):
    features = extract_features(url)
    prediction = lgb.predict(features)
    result = "Safe" if lb_make.inverse_transform(prediction)[0] == 'benign' else "Malicious"

    if result == "Safe":
        st.markdown(
            """
            <style>
            .main {
                background-color: green;
            }
            </style>
            """, unsafe_allow_html=True
        )
        st.success("The Domain is Safe to visit! ✅")
    else:
        st.markdown(
            """
            <style>
            .main {
                background-color: red;
            }
            </style>
            """, unsafe_allow_html=True
        )
        st.error("The Domain is Unsafe we recommend not to visit it! ❌")
