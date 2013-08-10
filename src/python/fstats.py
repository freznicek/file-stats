#!/usr/bin/env python

'''
File statistics (fstats)

Tool calculating various file statistics:
  size
  histogram
  entropy
  

Usage example:
  python ./fstats.py --load-data=./fstats.py --line-count --word-count --length --mode-length=read --histogram --entropy
  wc ./fstats.py
  
  
  #dd if=/dev/zero of=/tmp/r bs=1 count=1000000
  dd if=/dev/urandom of=/tmp/r bs=1 count=1000000
  wc /tmp/r
  python ./fstats.py --load-data=/tmp/r --line-count --word-count --length --mode-length=read --histogram --entropy


Source URLs:
 http://www.cs.uta.fi/~scott/mmm/Entropy.html
 http://www.forensickb.com/2013/03/file-entropy-explained.html
 http://gynvael.coldwind.pl/?id=158
 http://troydhanson.github.io/misc/Entropy.html
 http://stackoverflow.com/questions/990477/how-to-calculate-the-entropy-of-a-file
'''

import os
import sys
import math
import pickle
import optparse

# ---------------------------------------------------------------------------
# classes
# ---------------------------------------------------------------------------
class FileReader(object):
  
  def __init__(self, in_rmode = 'byte'):
    ''' public ctor
          reading mode: 'byte'
                        'line'
                        'none'
    '''
    self.fh = None;
    self.rmode = in_rmode;
    self.__buffer_length = 4096;
  
  def __del__(self):
    ''' public dtor closing the file '''
    self.close();
  
  def open(self, in_filename):
    ''' open file / stream '''
    self.filename = in_filename;
    self.fh = open(in_filename, 'r');
  
  def process(self):
    ''' process file / stream '''
    if(self.rmode == 'byte'):
      while True:
        buffer = self.fh.read(self.__buffer_length);
        
        for i_byte in buffer:
          self.on_byte(i_byte);
          
        if (len(buffer) == 0):
          break;
      
    elif(self.rmode == 'line'):
      for i_line in self.fh.readlines():
        self.on_line(i_line);
    else:
      self.on_file();
  
  def close(self):
    ''' close file / stream '''
    if( (self.fh != None) and (self.fh.closed == False) ):
      self.fh.close();



  # handlers (virtual)
  def on_byte(self, in_byte):
    ''' on byte / char handler / callback '''
    pass;
  
  def on_line(self, in_line):
    ''' on line handler / callback '''
    pass;

  def on_file(self):
    ''' on file handler / callback '''
    pass;


class Histogram(FileReader):
  
  def __init__(self):
    super(Histogram, self).__init__(in_rmode = 'byte');
    self.bcnt_arr = [];
    for i in range(256):
      self.bcnt_arr.append(0);

  def on_byte(self, in_byte):
    self.bcnt_arr[ord(in_byte)] += 1;
  
  def result(self):
    return(self.bcnt_arr);


class Entropy(Histogram):
  def __init__(self):
    super(Entropy, self).__init__();
    self.bcnt = 0;

  def on_byte(self, in_byte):
    super(Entropy, self).on_byte(in_byte);
    self.bcnt += 1;
  
  def result(self, in_percent_ena = False):
    ent_bits = 0;
    for i in range(256):
      if (self.bcnt_arr[i] == 0):
        continue;
      p = 1.0 * self.bcnt_arr[i] / self.bcnt;
      ent_bits -= p * math.log(p, 2);
    ent_percent = 100 * ent_bits / 8.0;
    
    if (in_percent_ena):
      return(ent_percent);
    else:
      return(ent_bits);

class LengthByRead(FileReader):
  
  def __init__(self):
    super(LengthByRead, self).__init__(in_rmode = 'byte');
    self.byte_cnt = 0;
  
  def on_byte(self, in_byte):
    self.byte_cnt += 1;
  
  def result(self):
    return(self.byte_cnt);

class LengthByStat(FileReader):
  def __init__(self):
    super(LengthByStat, self).__init__(in_rmode = 'none');
    self.byte_cnt = 0;
  
  def on_file(self):
    self.byte_cnt = os.stat(self.filename).st_size;
  
  def result(self):
    return(self.byte_cnt);


class WordCount(FileReader):
  ''' Word counter based on general FileReader concept '''
  def __init__(self):
    super(WordCount, self).__init__(in_rmode = 'line');
    self.word_cnt = 0;
  
  def on_line(self, in_line):
    self.word_cnt += len(in_line.split());
  
  def result(self):
    return(self.word_cnt);

class LineCount(FileReader):
  ''' Line counter based on general FileReader concept '''
  def __init__(self):
    super(LineCount, self).__init__(in_rmode = 'line');
    self.line_cnt = 0;
  
  def on_line(self, in_line):
    self.line_cnt += 1;
  
  def result(self):
    return(self.line_cnt);


# common methods
# ---------------------------------------------------------------------------



# main() definition
# ---------------------------------------------------------------------------
def main(in_opts):
  print in_opts;
  
  if (in_opts['line_count']):
    lc = LineCount();
    lc.open(in_opts['load_data']);
    lc.process();
    lc.close();
    print lc.result();
  
  if (in_opts['word_count']):
    wc = WordCount();
    wc.open(in_opts['load_data']);
    wc.process();
    wc.close();
    print wc.result();

  if (in_opts['length']):
    l = LengthByRead();
    if (in_opts['mode_length'] == 'stat'):
      l = LengthByStat();
    l.open(in_opts['load_data']);
    l.process();
    l.close();
    print l.result();
  
  if (in_opts['histogram']):
    h = Histogram();
    h.open(in_opts['load_data']);
    h.process();
    h.close();
    print h.result();

  if (in_opts['entropy']):
    e = Entropy();
    e.open(in_opts['load_data']);
    e.process();
    e.close();
    print e.result(), e.result(True);


# main() call
# ---------------------------------------------------------------------------
if __name__ == "__main__":

  # parameters definition and parsing
  # -------------------------------------------------------------------------
  usage_msg = "usage: %prog [options]";
  op = optparse.OptionParser(usage=usage_msg);

  # define parameters
  # -------------------------------------------------------------------------
  
  op.add_option("--load-data", dest="load_data", type="string",
                action="store", default='<stdin>',
                help="Load data from a file / STDIN (def: %default)", metavar="CFN");
  
  op.add_option("--histogram", dest="histogram", 
                action="store_true", default=False,
                help="Report data histogram (def: %default)");
  op.add_option("--entropy", dest="entropy", action="store_true", default=False,
                help="Report data entropy (def: %default)");
  op.add_option("--length", dest="length", action="store_true", default=False,
                help="Report data length/size (def: %default)");
  op.add_option("--line-count", dest="line_count", action="store_true", default=False,
                help="Report data line count (def: %default)");
  op.add_option("--word-count", dest="word_count", action="store_true", default=False,
                help="Report data word count (def: %default)");
  
  op.add_option("--mode-length", dest="mode_length", type='string',
                action="store", default='stat',
                help="Data length gathering method (def: %default)");

  
  op.add_option("--help-long", dest="help_long",
                action="store_true", default=False,
                help="Long help");
  
  op.add_option("-v", "--verbose", dest="verbose",
                action="store_true", default=False,
                help="Verbose mode");
  
  (opts, args) = op.parse_args();
  
  if (opts.help_long):
    print __doc__;
    op.print_help();
    sys.exit(0);
  
  int_opts = { };
  int_opts = eval('%s' % opts);
  
  main(int_opts);


# ---------------------------------------------------------------------------
# eof
# ---------------------------------------------------------------------------
