
"""Remove Python comments from source files under a directory.

Usage: python scripts/remove_comments.py [root_dir]
"""
import io 
import os 
import sys 
import tokenize 


def remove_comments_from_bytes (src_bytes ):
    try :
        tokens =list (tokenize .tokenize (io .BytesIO (src_bytes ).readline ))
    except Exception :
        return src_bytes 
    out =[]
    for tok in tokens :

        if tok .type ==tokenize .COMMENT :
            continue 
        out .append ((tok .type ,tok .string ))
    try :
        new =tokenize .untokenize (out )
    except Exception :
        return src_bytes 
    if isinstance (new ,str ):
        return new .encode ('utf-8')
    return new 


def should_exclude (path ,excludes ):
    for ex in excludes :
        if os .path .commonpath ([os .path .abspath (path ),os .path .abspath (ex )])==os .path .abspath (ex ):
            return True 
    return False 


def main (root ):
    excludes =[os .path .join (root ,'venv'),os .path .join (root ,'.git')]
    changed_files =[]
    for dirpath ,dirnames ,filenames in os .walk (root ):

        if any (os .path .commonpath ([os .path .abspath (dirpath ),os .path .abspath (e )])==os .path .abspath (e )for e in excludes ):
            continue 
        for fn in filenames :
            if not fn .endswith ('.py'):
                continue 
            path =os .path .join (dirpath ,fn )
            if should_exclude (path ,excludes ):
                continue 
            with open (path ,'rb')as f :
                orig =f .read ()
            new =remove_comments_from_bytes (orig )
            if new !=orig :
                with open (path ,'wb')as f :
                    f .write (new )
                changed_files .append (path )
    print ('Stripped comments from',len (changed_files ),'files')
    for p in changed_files :
        print ('  ',p )


if __name__ =='__main__':
    root =sys .argv [1 ]if len (sys .argv )>1 else os .getcwd ()
    main (root )
