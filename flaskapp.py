from flask import Flask,render_template,request,url_for,redirect,session as sess,make_response,send_file,jsonify,request
import boto3
import uuid
import botocore
import hashlib
from boto3.session import Session
from flask import jsonify
import zipfile
import StringIO
app = Flask(__name__)

# -------------------------------- Hash APIs -----------------------------#

def generate_hash(hashData):
    return str(hashlib.sha224(hashData).hexdigest())


app.secret_key = "1|D0N'T|W4NT|TH15|T0|3E|R4ND0M"
AWS_ACCESS_KEY_ID='AKIAIORRAXNXKTJV53DQ'
AWS_SECRET_ACCESS_KEY='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'
REGION_NAME='us-east-1'
POOL_ID='us-east-1_rzRdUDZbw'
clientId='6cp837r2tpeqcik9kkgkvbc5r3'
bucketNameTag='profile'
session = Session(
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=REGION_NAME
)
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register',methods=['POST','GET'])
def register():
    information=None
    error=None
    success=None
    try:
        information=request.args.get('information')
    except:
        pass
    try:
        error=request.args.get('error')
    except:
        pass
    try:
        success=request.args.get('success')
    except:
        pass
    if 'AccessToken' in sess:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print username+' '+password
        client=session.client('cognito-idp')
        print client
        uuidValue=str(uuid.uuid4())
        try:
            output = client.sign_up(ClientId=clientId, Username=username, Password=password, UserAttributes=[
                {
                    'Name': 'preferred_username',
                    'Value': username
                },
                {
                'Name': 'profile',
                'Value': uuidValue
                }
            ])
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'UsernameExistsException':
                print "User already exists"
            error= 'User already exists'
            return render_template("login.html",success=success,error=error,information=information)
        except botocore.exceptions.ParamValidationError:
            print "invalid password"
            error= "Password should be of atleast 6 characters"
            return render_template("register.html",success=success,error=error,information=information)

        print output
        response = client.admin_confirm_sign_up(
            UserPoolId=POOL_ID,
            Username=username
        )
        print response
        return render_template("login.html",success=success,error=error,information=information)
    return render_template("register.html",success=success,error=error,information=information)



@app.route('/login',methods=['POST','GET'])
def login():
    information = None
    error = None
    success = None
    try:
        information = request.args.get('information')
    except:
        pass
    try:
        error = request.args.get('error')
    except:
        pass
    try:
        success = request.args.get('success')
    except:
        pass
    if 'AccessToken' in sess:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        #print username+' '+password
        #connection = boto3.CognitoIdentityConnection(aws_access_key_id=AWS_ACCESS_KEY_ID,aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        client=session.client('cognito-idp')
        #print client
        uuidValue=str(uuid.uuid4())
        try:
            response = client.admin_initiate_auth(
                UserPoolId=POOL_ID,
                ClientId=clientId,
                AuthFlow='ADMIN_NO_SRP_AUTH',
                AuthParameters={
                    'USERNAME': username, 'PASSWORD': password
                },
            )
            sess['AccessToken']=str(response['AuthenticationResult']['AccessToken'])
            print 'redirecing'
            return redirect(url_for('dashboard'))#render_template("dashboard.html")
        except Exception as e:
            print e
            error="Invalid username/password"
            return render_template("login.html",success=success,error=error,information=information)
    return render_template("login.html",success=success,error=error,information=information)


def detUserDetails(user,field):
    for att in user['UserAttributes']:
        if att['Name'] == field:
            return att['Value']
    return None;

@app.route("/dashboard.html",methods=['POST','GET'])
def dashboard():
    information = None
    error = None
    success = None
    try:
        information = request.args.get('information')
    except:
        pass
    try:
        error = request.args.get('error')
    except:
        pass
    try:
        success = request.args.get('success')
    except:
        pass
    print success
    if 'AccessToken' in sess:
        accesToken=sess['AccessToken']
        identity_client = session.client('cognito-idp')
        try:
            userDetails = identity_client.get_user(
                AccessToken=accesToken
            )
        except :
            sess.pop('AccessToken', None)
            return redirect(url_for('login',error="Invalid session"))
        s3_client=session.client('s3')
        s3_resource=session.resource('s3')
        bucket_name=detUserDetails(userDetails,bucketNameTag)
        username=userDetails['Username']
        try:
            s3_resource.meta.client.head_bucket(Bucket=bucket_name)
        except botocore.exceptions.ClientError as e:
            error_code = int(e.response['Error']['Code'])
            if error_code == 404:
                s3_resource.create_bucket(Bucket=bucket_name)
        bucket = s3_resource.Bucket(bucket_name)
        list1 = []
        for key in bucket.objects.all():
            list2=[]
            object1 = s3_client.get_object(Bucket=bucket_name,Key=key.key)
            metaData = object1['Metadata']
            resp=object1['ResponseMetadata']['HTTPHeaders']
            list2.append(str(key.key))
            list2.append(metaData['name'])
            list2.append(resp['last-modified'])
            list2.append(setSizeWithUnits(resp['content-length']))
            list1.append(list2)
        if(len(list1)!=0):
            return render_template('dashboard.html', userna=username, outputData=list1,success=success,error=error,information=information)
        else:
            return render_template('dashboard.html', userna=username,success=success,error=error,information=information)
    else:
        return redirect(url_for('login',error='Please login'))

def setSizeWithUnits(size):
    try:
        intvalue=float(size)

        if intvalue <1024:
            return str(intvalue)+' Bytes'
        elif intvalue/1024 <1024:
            return str(intvalue/1024)+" KB"
        elif intvalue/(1024*1024):
            return str(intvalue/(1024*1024))+" MB"
        else:
            return str(intvalue/(1024*1024*1024))+" GB"
    except:
        pass
    return size
@app.route('/<userNam>/upload',methods=['POST'])
def addFiles(userNam):
    if request.method == 'POST':
        if 'AccessToken' in sess:
            userDetails=""
            accesToken = sess['AccessToken']
            s3_resource = session.resource('s3')
            try:

                identity_client = session.client('cognito-idp')
                userDetails = identity_client.get_user(
                    AccessToken=accesToken
                )
            except:
                sess.pop('AccessToken', None)
                return redirect(url_for('login'))
            bucket_name = detUserDetails(userDetails, bucketNameTag)
            username = userDetails['Username']
            uploadedFiles=request.files.getlist('fileToUpload')
            for uploadedFile in uploadedFiles:
                fileName=uploadedFile.filename
                if fileName=='':
                    redirect(url_for('dashboard', userNam=username))
                data=uploadedFile.read()
                hash_data = generate_hash(data)
                metadata = {}
                metadata['Name'] = fileName
                metadata['Hash']=hash_data
                key=str(uuid.uuid4())
                s3_resource.Bucket(bucket_name).put_object(Key=key+'-'+fileName, Body=data, Metadata=metadata)
                print "Ready for redirect"
            return redirect(url_for('dashboard', userNam=userNam,success='Upload successful'))
        else:
            return redirect(url_for('login',error='Please login'))
    return redirect(url_for('login'))

@app.route('/<userNam>/Download',methods=['POST'])
def download(userNam):
    print request.method
    if request.method.upper() == 'POST':
        print 'post'
        if 'AccessToken' in sess:
            userDetails=""
            accesToken = sess['AccessToken']
            print accesToken
            s3_resource = session.resource('s3')
            try:

                identity_client = session.client('cognito-idp')
                userDetails = identity_client.get_user(
                    AccessToken=accesToken
                )
            except Exception as e:
                print e;
                sess.pop('AccessToken', None)
                return redirect(url_for('login'))
            bucket_name = detUserDetails(userDetails, bucketNameTag)
            username = userDetails['Username']

            downloafList=request.form.getlist('filenames')
            if len(downloafList) == 1:
                obj=s3_resource.Object(bucket_name=bucket_name,key=downloafList[0])
                response = obj.get()
                data = response['Body'].read()
                response = make_response(data);
                metadata=obj.metadata

                response.headers["Content-Disposition"] = "attachment; filename=" + metadata['name']
                return response
            elif len(downloafList)>1:
                zipped_file = StringIO.StringIO()
                with zipfile.ZipFile(zipped_file, 'w') as zip:
                    for downloadobj in downloafList:
                        obj = s3_resource.Object(bucket_name=bucket_name, key=downloadobj)
                        response = obj.get()
                        attachmentDetails = response['Body'].read()
                        metadata = obj.metadata
                        fileName=metadata['name']
                        zip.writestr(fileName, attachmentDetails)
                zipped_file.seek(0)
                response = make_response(send_file(filename_or_fp=zipped_file, mimetype='application/zip', as_attachment=True,
                              attachment_filename=username + ".zip"))
                response.headers["Content-Disposition"] = "attachment; filename=" + username + ".zip"
                return response

        else:
            sess.pop('AccessToken', None)
            return redirect(url_for('login', error='Please login'))

    return redirect(url_for('login'))

@app.route('/<userNam>/logout')
def logout(userNam):
    if 'AccessToken' in sess:
        try:
            identity_client = session.client('cognito-idp')
            response = identity_client.global_sign_out(
                AccessToken=sess['AccessToken']
            )
        except :
            pass
        sess.pop('AccessToken', None)
    return redirect(url_for('login',success='Logout Successful'))


@app.route('/<userNam>/delete',methods=['POST'])
def delete(userNam):
    if request.method == 'POST':
        if 'AccessToken' in sess:
            userDetails = ""
            accesToken = sess['AccessToken']
            s3_resource = session.resource('s3')
            try:

                identity_client = session.client('cognito-idp')
                userDetails = identity_client.get_user(
                    AccessToken=accesToken
                )
            except Exception as e:
                print e;
                sess.pop('AccessToken', None)
                return redirect(url_for('login', error='Please login'))
            bucket_name = detUserDetails(userDetails, bucketNameTag)
            delItems = request.form.getlist('filenames')
            for delItem in delItems:
                print 'deleting '+delItem
                obj = s3_resource.Object(bucket_name=bucket_name, key=delItem)
                obj.delete()
                #obj.delete()
                print obj

            return redirect(url_for('dashboard', userNam=userNam, success = 'Delete successful'))
    return redirect(url_for('dashboard',userNam=userNam ))

@app.route('/getURL')
def getURL():
    objId = request.args.get('objId', '')
    if 'AccessToken' in sess:
        accesToken = sess['AccessToken']
        s3client = session.client('s3')
        userDetails=''
        try:

            identity_client = session.client('cognito-idp')
            userDetails = identity_client.get_user(
                AccessToken=accesToken
            )
        except Exception as e:
            print e;
            sess.pop('AccessToken', None)
            return jsonify(result='Error:Please login')
        bucket_name = detUserDetails(userDetails, bucketNameTag)
        #username = userDetails['Username']
        try:
            url = s3client.generate_presigned_url(ClientMethod='get_object', Params={
                'Bucket': bucket_name,
                'Key': objId
            })
        except Exception as e:
               print e;
               return jsonify(result='Error:Please login')
        return jsonify(result=url)
    return jsonify('Error:Please login')


if __name__ == '__main__':
    app.run()
