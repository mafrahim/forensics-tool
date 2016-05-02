
#! /usr/bin/python
# -*- coding: utf-8 -*-

import os
import re
import sys
import logging
import argparse
import subprocess
import hashlib
import pyPdf
import sqlite3
import magic
import unicodecsv as csv
import string
import codecs


from PIL import Image
from PIL.ExifTags import TAGS

try:
    from sqlalchemy import Column, Integer, Float, String, Text
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import create_engine
except ImportError as e:
    print "Module `{0}` not installed".format(error.message[16:])
    sys.exit()

# === SQLAlchemy Config ============================================================================
Base = declarative_base()

logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)

# === Database Classes =============================================================================
class imageInfo(Base):

    __tablename__ = 'image'

    id = Column(Integer,primary_key = True)
    Filename = Column(String)
    Tag = Column(String)
    Value = Column(String)
    md5 = Column(String)

    def __init__(self,Filename,Tag,Value,md5,**kwargs):
        self.Filename=Filename
        self.Tag=Tag
        self.Value=Value
        self.md5=md5

# === Database Classes =============================================================================
class imageInfo2(Base):

    __tablename__ = 'pdf'

    id = Column(Integer,primary_key = True)
    Filename = Column(String)
    Tag = Column(String)
    Value = Column(String)
    md5 = Column(String)

    def __init__(self,Filename,Tag,Value,md5,**kwargs):
        self.Filename=Filename
        self.Tag=Tag
        self.Value=Value
        self.md5=md5

# === Fingerprint Classes =========================================================================
class osFingerprinter(object):
    def __init__(self, img = ''):
        if img == '' or not os.path.exists(img):
            raise Exception('No disk image provided')
           
        self.img = img
        self.fn  = os.path.splitext(os.path.basename(img))[0]
        self.dir = '{0}/extract/{1}'.format(os.path.dirname(os.path.abspath(__file__)), self.fn)
        if not os.path.exists(self.dir): os.makedirs(self.dir)

        self.db = 'fingerprint.db'
        self.engine = create_engine('sqlite:///'+self.db, echo=False)
        Base.metadata.create_all(self.engine)

        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def fingerprint(self):
        try:
            info = subprocess.check_output(["fsstat",self.img])
            self.fp = self.__parseFingerprint(info)
        except Exception as e:
            raise Exception('Error fingerprinting image.')


    def carve(self):
        try:
            subprocess.check_output(["tsk_recover","-e",self.img,self.dir])
            #subprocess.check_output(["tsk_loaddb".format(self.dir, self.fn),self.img])
        except:
            raise Exception('Error carving image.')

#inspiration from webpage.py 
    def write_pdf(self,filename,item,dat,md5):
	self.filename=filename
	row = imageInfo2(filename.decode("utf-8"),str(item), str(dat),str(md5))
	self.session.add(row)
	self.session.commit()

    def write_exif(self,exif,filename,md5):
	self.exif=exif
	for tag,value in exif.iteritems():
		self.filename=filename
		row = imageInfo(filename.decode("utf-8"),str(tag), str(value),str(md5))
		self.session.add(row)
		self.session.commit()

    def exif_error(self,filename,item,dat,md5):
        self.filename=filename
        row = imageInfo(filename.decode("utf-8"),str(item), str(dat),str(md5))
        self.session.add(row)
        self.session.commit()

#http://stackoverflow.com/questions/10522830/how-to-export-sqlite-to-csv-in-python-without-being-formatted-as-a-list
def export_csv():
	DATABASE = sqlite3.connect('fingerprint.db')
	cur = DATABASE.cursor()
	dat = cur.execute("SELECT Filename, Tag, Value, md5 FROM image").fetchall()
        dat2 = cur.execute("SELECT Filename, Tag, Value, md5 FROM pdf").fetchall()

	f = codecs.open('fingerprint.csv','wb')
        wrtr = csv.writer(f)
        f.seek(0)
        wrtr.writerow(['File_Name','Tag','Value','MD5'])
    	for row in dat:
            wrtr.writerow(row)

        for row in dat2:
            wrtr.writerow(row)
        f.flush()
	f.close()
	DATABASE.close()

#http://joelverhagen.com/blog/2011/02/md5-hash-of-file-in-python/
def md5Checksum(filePath):
    with open(filePath, 'rb') as fh:
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()


def main(argv):
    parser = argparse.ArgumentParser(description='OS Fingerprinting and Carving')
    parser.add_argument('img',help='Disk Image(s) to be analyzed; newline delimited text file or single filename')
    args=parser.parse_args()

    try:
        if os.path.isfile(args.img) and os.path.splitext(os.path.basename(args.img))[1] == '.txt':
            with open(args.img) as ifile:
                imgs = ifile.read().splitlines()
        else:
            raise Exception('')
    except:
        try:
            imgs = [img for img in args.img.split(',')]
        except:
            imgs = args.img

    for img in imgs:
        osf = osFingerprinter(img)
        #osf.fingerprint()
        osf.carve()
   
    for dirname, dirnames, filenames in os.walk('./extract/'):
        for fn in filenames:
            filename = fn
            filetype = magic.from_file(os.path.join(dirname, fn),mime=True)
            
#from pdf.py provided in the class
            if "pdf" in filetype:
                try:
                    pdf = pyPdf.PdfFileReader(file(os.path.join(dirname, fn), 'rb'))
                    info = pdf.getDocumentInfo()
                    md5 = md5Checksum(os.path.join(dirname, fn))
                    #print '[*] PDF Metadata: {0}'.format(fn)
                    for item, dat in info.items():
                        osf.write_pdf(filename,item,str(dat),md5)
                        #try:
                            #print '[+] {0}: {1}'.format(item, pdf.resolvedObjects[0][1][item])
                            #                   
                        #except:
                            #print '[+] {0}: {1}'.format(item, dat)
                except Exception, e:
                    print "\n" + dirname +  fn 
                    print e
                    osf.write_pdf(fn,"error",e,md5)

#From exif.py provided in the class
            elif "image" in filetype:
                exif = {}
                md5 = md5Checksum(os.path.join(dirname, fn))
                try:
                    img = Image.open(os.path.join(dirname, fn))
                    info = img._getexif()
                    for tag, value in info.items():
                        decoded = TAGS.get(tag, tag)
                        #print "[+] " + decoded + ":", value
                        exif[decoded] = value

                except Exception, e:
                    exif = exif
                    print "\n" + dirname + " " +  fn
                    print e
                    osf.exif_error(fn,"error",e,md5)

                osf.write_exif(exif,filename,md5)

    export_csv()
    print 'All images analyzed. Extracted files saved in `./extract/`. Image information saved in `fingerprint.db` and exported as `fingerprint.csv` '

if __name__ == '__main__':
    main(sys.argv)
