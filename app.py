from datetime import datetime

import pymongo
import requests
from bson.objectid import ObjectId

from flask import Flask, abort, redirect, render_template, request, url_for
from pysafebrowsing import SafeBrowsing

app = Flask(__name__)

config = {
    "server": "flask_mongo:27017",
}

connector = "mongodb://{}".format(config["server"])
client = pymongo.MongoClient(connector)
db = client["flaskapp"]


@app.route("/")
def main():
    return render_template('main.html')


@app.route("/safebrowsing", methods=['POST'])
def get_safe_browsing():
    url_to_check = request.form['url']
    s = SafeBrowsing("<APIKEY_HERE>") # This lib uses Google SafeBrowsing API, to get an API access https://console.developers.google.com/apis/dashboard
    r = s.lookup_urls([request.form['url']])
    r[url_to_check]['malicious']
    response = {
        "url": url_to_check,
        "malicious": r[url_to_check]['malicious'],
        "created_at": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
    }
    res = db.safebrowsing.update(
        {'url': response['url']}, response, upsert=True)
    return render_template('main.html', response=response)


@app.route("/list", methods=['GET'])
def list_safebrowsing():
    count = db.safebrowsing.count_documents({})
    safebrowsings = db.safebrowsing.find({}).limit(5)
    return render_template('list.html', count=count, safebrowsings=safebrowsings)


@app.route("/safebrowsing/<idnum>", methods=['GET'])
def safebrowsing(idnum):
    safebrowsing = db.safebrowsing.find_one({'_id': ObjectId(idnum)})
    app.logger.info(idnum)
    if not safebrowsing:
        abort(404)
    return render_template('safebrowsing.html', safebrowsing=safebrowsing)


@app.errorhandler(404)
def not_found(error):
    app.logger.info(error)
    return render_template('404.html'), 404


@app.route("/get", methods=['POST'])
def get():
    url = request.form['url']
    safebrowsings = list(db.safebrowsing.find({'url': {'$regex': '.*'+url+'.*'}}))
    if safebrowsings:
        return render_template('main.html', safebrowsings=safebrowsings)
    return render_template('main.html', error="There are no safe browsing with this url")
