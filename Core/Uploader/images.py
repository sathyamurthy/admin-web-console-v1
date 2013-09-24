import PIL
from PIL import Image
import os

def ImageVersion(version,img,file,version_path):
    #print version_path
    response_data = {}
    try:
        basewidth = version['width']
        width, height = img.size
        wpercent = (basewidth/float(img.size[0]))
        hsize = int((float(img.size[1])*float(wpercent)))

        #img = img.resize((basewidth,hsize), PIL.Image.ANTIALIAS)Image.BICUBIC
        img = img.resize((basewidth,hsize), PIL.Image.BICUBIC)
        img.save(os.path.join(version_path,file.name), "JPEG",quality=90)
        response_data = {'name':version['name'],'width':version['width'],'height':hsize,'path':os.path.join(version_path,file.name)}
        #response_data[version['name']].append({'width':version['width']})
        #response_data[version['name']].append({'height':hsize})
        #response_data[version['name']].append({'path':os.path.join(version_path,file.name)})
    except IOError:
        raise
        #print "cannot create thumbnail for", file.name
                                
    return response_data
