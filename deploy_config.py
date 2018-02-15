#coding=UTF-8

bind = '0.0.0.0:8000' #Bound port
workers = 1 #worker Quantity
backlog = 2048
debug = True
proc_name = 'gunicorn.pid'
pidfile = '/var/log/gunicorn/debug.log'
loglevel = 'debug'
