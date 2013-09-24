# imports

# import the django settings
from django.conf import settings
# for generating json
from django.utils import simplejson
# for loading template
from django.template import Context, loader
# for csrf
from django.core.context_processors import csrf
# for HTTP response
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
# for os manipulations
import os
from UserManagement.authendication import CheckForAuthentication,CheckForAuthorization
import sys
from Assets.models import Extended
from Uploader.models import Files

def Upload(request):
    """
    
    ## View for file uploads ##

    It does the following actions:
        - displays a template if no action have been specified
        - upload a file into unique temporary directory
                unique directory for an upload session
                    meaning when user opens up an upload page, all upload actions
                    while being on that page will be uploaded to unique directory.
                    as soon as user will reload, files will be uploaded to a different
                    unique directory
        - delete an uploaded file

    ## How Single View Multi-functions ##

    If the user just goes to a the upload url (e.g. '/upload/'), the request.method will be "GET"
        Or you can think of it as request.method will NOT be "POST"
    Therefore the view will always return the upload template

    If on the other side the method is POST, that means some sort of upload action
    has to be done. That could be either uploading a file or deleting a file

    For deleting files, there is the same url (e.g. '/upload/'), except it has an
    extra query parameter. Meaning the url will have '?' in it.
    In this implementation the query will simply be '?f=filename_of_the_file_to_be_removed'

    If the request has no query parameters, file is being uploaded.

    """

    # used to generate random unique id
    import uuid

    # settings for the file upload
    #   you can define other parameters here
    #   and check validity late in the code
    options = {
        # the maximum file size (must be in bytes)
        "maxfilesize": 16 * 2 ** 20, # 2 Mb
        # the minimum file size (must be in bytes)
        "minfilesize": 1 * 2 ** 10, # 1 Kb
        # the file types which are going to be allowed for upload
        #   must be a mimetype
        "acceptedformats": (
            "image/jpeg",
            "image/png",
            )
    }

    if CheckForAuthorization().is_authorized(request,'Extended.Edit'):
        # POST request
        #   meaning user has triggered an upload action
        if request.method == 'POST':
            # figure out the path where files will be uploaded to
            # PROJECT_ROOT is from the settings file
            temp_path = os.path.join(settings.EXTENDED_CONTENT_ROOT, "")
            # if 'f' query parameter is not specified
            # file is being uploaded
            if not ("f" in request.GET.keys()): # upload file

                # make sure some files have been uploaded
                if not request.FILES:
                    return HttpResponseBadRequest('Must upload a file')

                #print >> sys.stdout,request
                sequence = False
                overwrite = False

                try:
                    overwrite = request.POST[u'overwrite']
                except:
                    pass
                    
                try:
                    sequence = request.POST[u'sequence']
                except:
                    pass
                                    
                Gallery = Extended.objects.get(pk=request.POST[u'gallery_id'])
                #import pdb
                #pdb.set_trace()
                temp_path = os.path.join(settings.EXTENDED_CONTENT_ROOT, "")
                relative_path =  settings.RELATIVE_EXTENDED_CONTENT
                #print >> sys.stdout,overwrite
                #print >> sys.stdout,Gallery.gallery_id

                # make sure unique id is specified - VERY IMPORTANT
                # this is necessary because of the following:
                #       we want users to upload to a unique directory
                #       however the uploader will make independent requests to the server
                #       to upload each file, so there has to be a method for all these files
                #       to be recognized as a single batch of files
                #       a unique id for each session will do the job
                if not request.POST[u"uid"]:
                    return HttpResponseBadRequest("UID not specified.")
                    # if here, uid has been specified, so record it
                #uid = request.POST[u"uid"]
                uid = str(Gallery.pk)

                # update the temporary path by creating a sub-folder within
                # the upload folder with the uid name
                temp_path = os.path.join(temp_path, uid)
                relative_path = os.path.join(relative_path, uid)
                # get the uploaded file
                file = request.FILES[u'files[]']

                # initialize the error
                # If error occurs, this will have the string error message so
                # uploader can display the appropriate message
                error = False

                # check against options for errors

                # file size
                if file.size > options["maxfilesize"]:
                    error = "maxFileSize"
                if file.size < options["minfilesize"]:
                    error = "minFileSize"
                    # allowed file type
                if file.content_type not in options["acceptedformats"]:
                    error = "acceptFileTypes"


                # the response data which will be returned to the uploader as json
                limited_data = {
                    "name": file.name,
                    "size": file.size,
                }
                response_data = {
                    "name": file.name,
                    "size": file.size,
                    "type": file.content_type
                }

                # if there was an error, add error message to response_data and return
                if error:
                    # append error message
                    response_data["error"] = error
                    # generate json
                    response_data = simplejson.dumps([response_data])
                    # return response to uploader with error
                    # so it can display error message
                    return HttpResponse(response_data, mimetype='application/json')


                # make temporary dir if not exists already
                if not os.path.exists(temp_path):
                    os.makedirs(temp_path)

                # get the absolute path of where the uploaded file will be saved
                # all add some random data to the filename in order to avoid conflicts
                # when user tries to upload two files with same filename
                #filename = os.path.join(temp_path, str(uuid.uuid4()) + file.name)
                filename = os.path.join(temp_path,  file.name)
                relative_path = os.path.join(relative_path, file.name)
                # open the file handler with write binary mode
                if not overwrite.lower()=="true":
                    if os.path.isfile(filename):
                        response_data["error"] = "File already exist"
                        response_data = simplejson.dumps([response_data])
                        return HttpResponse(response_data, mimetype='application/json')

                destination = open(filename, "wb+")
                # save file data into the disk
                # use the chunk method in case the file is too big
                # in order not to clutter the system memory
                for chunk in file.chunks():
                    destination.write(chunk)
                    # close the file
                destination.close()
                try:
                    import PIL
                    from PIL import Image
                    basewidth = 160
                    img = Image.open(filename)
                    width, height = img.size
                    response_data['width'] =width
                    response_data['height'] =height
                    wpercent = (basewidth/float(img.size[0]))
                    hsize = int((float(img.size[1])*float(wpercent)))
                    #img = img.resize((basewidth,hsize), PIL.Image.ANTIALIAS)
                    img = img.resize((basewidth,hsize), PIL.Image.ANTIALIAS)
                    img.save(os.path.join(temp_path,os.path.splitext(file.name)[0])+"_"+str(basewidth)+os.path.splitext(file.name)[1], "JPEG")
                    response_data['thumbnail_abs'] = os.path.join(temp_path,os.path.splitext(file.name)[0])+"_"+str(basewidth)+os.path.splitext(file.name)[1]
                    response_data['thumbnail_rel'] = os.path.join(settings.RELATIVE_EXTENDED_CONTENT, uid,os.path.splitext(file.name)[0])+"_"+str(basewidth)+os.path.splitext(file.name)[1]
                    response_data['thumbnail'] = os.path.join(settings.RELATIVE_EXTENDED_CONTENT, uid,os.path.splitext(file.name)[0])+"_"+str(basewidth)+os.path.splitext(file.name)[1]
                    limited_data['thumbnail'] = os.path.join(settings.RELATIVE_EXTENDED_CONTENT, uid,os.path.splitext(file.name)[0])+"_"+str(basewidth)+os.path.splitext(file.name)[1]
                except IOError:
                    print "cannot create thumbnail for", filename
                    raise
                    
                
                FileId = ""
                try:
                    insertFile = Files.objects.filter(gallery__exact=Gallery.pk).filter(path=filename)
                    #print >> sys.stdout,insertFile.count
                    
                    if not insertFile:
                        newFile = Files(name =file.name, path=filename,gallery=Gallery,relative_path=relative_path,extension=os.path.splitext(file.name)[1], file_type=file.content_type,properties = response_data,limited_properties=limited_data)
                        from django.db.models import Max
                        aggr =  Files.objects.filter(gallery__exact=Gallery.pk).aggregate(Max('position'))
                        #print >> sys.stdout, aggr['position__max']
                        if aggr['position__max'] is None:
                            newFile.position = 1
                        else:
                             newFile.position =  aggr['position__max'] + 1
                        newFile.save()
                        FileId = newFile.pk
                    else:
                        oldFile = insertFile.get()
                        oldFile.extension=file.content_type
                        oldFile.properties=response_data
                        oldFile.relative_path=relative_path
                        oldFile.limited_properties = limited_data
                        oldFile.save()
                        FileId = oldFile.pk
                        #print >> sys.stdout,oldFile
                        #insertFile.properties = response_data
                        #insertFile.save()
                    
                except:
                    raise

                

                # here you can add the file to a database,
                #                           move it around,
                #                           do anything,
                #                           or do nothing and enjoy the demo
                # just make sure if you do move the file around,
                # then make sure to update the delete_url which will be send to the server
                # or not include that information at all in the response...

                # allows to generate properly formatted and escaped url queries
                import urllib

                # url for deleting the file in case user decides to delete it
                #response_data["delete_url"] = request.path + "?" + urllib.urlencode({"f": uid + "/" + os.path.split(filename)[1]})
                # specify the delete type - must be POST for csrf
                FileId = str(FileId)
                response_data["delete_url"] = request.path + "?" + urllib.urlencode({"f":FileId})
                response_data["delete_type"] = "POST"

                # generate the json data
                response_data = simplejson.dumps([response_data])
                # response type
                response_type = "application/json"

                # QUIRK HERE
                # in jQuey uploader, when it falls back to uploading using iFrames
                # the response content type has to be text/html
                # if json will be send, error will occur
                # if iframe is sending the request, it's headers are a little different compared
                # to the jQuery ajax request
                # they have different set of HTTP_ACCEPT values
                # so if the text/html is present, file was uploaded using jFrame because
                # that value is not in the set when uploaded by XHR
                if "text/html" in request.META["HTTP_ACCEPT"]:
                    response_type = "text/html"

                # return the data to the uploading plugin
                return HttpResponse(response_data, mimetype=response_type)

            else: # file has to be deleted

                # get the file path by getting it from the query (e.g. '?f=filename.here')
                #filepath = os.path.join(temp_path, request.GET["f"])
                file_id =  request.GET["f"]

                try:
                    Gal = Files.objects.get(pk=file_id)
                    try:
                        #print >> sys.stdout,Gal.properties['thumbnail_abs']
                        if Gal.properties['thumbnail_abs'] is not None:
                            if os.path.isfile(Gal.properties['thumbnail_abs']):
                                os.remove(Gal.properties['thumbnail_abs'])
                    except:
                        pass
                    if os.path.isfile(Gal.path):
                        os.remove(Gal.path)
                    Gal.delete()   
                except Files.DoesNotExist:
                    return HttpResponseBadRequest("File does not exist")
                except:
                    raise

                # make sure file exists
                # if not return error
                #if not os.path.isfile(filepath):
                #    return HttpResponseBadRequest("File does not exist")


                # delete the file
                # this step might not be a secure method so extra
                # security precautions might have to be taken
                #os.remove(filepath)

                # generate true json result
                # in this case is it a json True value
                # if true is not returned, the file will not be removed from the upload queue
                response_data = simplejson.dumps(True)

                # return the result data
                # here it always has to be json
                return HttpResponse(response_data, mimetype="application/json")

        else: #GET
            # load the template
            #print >> sys.stdout,CheckForAuthorization().is_authorized(request,'Extended.Edit')
                t = loader.get_template("base_templates/Extended/upload.html")
                c = Context({
                    # the unique id which will be used to get the folder path
                    "uid": uuid.uuid4(),
                    # these two are necessary to generate the jQuery templates
                    # they have to be included here since they conflict with django template system
                    "open_tv": u'{{',
                    "close_tv": u'}}',
                    # some of the parameters to be checked by javascript
                    "maxfilesize": options["maxfilesize"],
                    "minfilesize": options["minfilesize"],
                    })
                # add csrf token value to the dictionary
                c.update(csrf(request))
                # return
                return HttpResponse(t.render(c))
    else:
        return HttpResponse('Unauthorized', status=401)
