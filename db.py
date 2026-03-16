import sqlite3
from flask import g

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            "database.db",
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_one(query, args=()):
    query = query.replace("%s", "?")
    cur = get_db().execute(query, args)
    return cur.fetchone()

def query_all(query, args=()):
    query = query.replace("%s", "?")
    cur = get_db().execute(query, args)
    return cur.fetchall()

def execute(query, args=()):
    query = query.replace("%s", "?")
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur