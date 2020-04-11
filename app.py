import time
import redis
from flask.cli import cli
from rq import Connection, Worker, Queue
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, make_response
from flask_redis import FlaskRedis
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, get_jwt_identity
)
from elasticsearch import Elasticsearch

# REDIS_URL = "redis://localhost:6379/0"
app = Flask(__name__)
redis_client = FlaskRedis(app)
app.config['JSON_SORT_KEYS'] = False
es = Elasticsearch()
app.config["REDIS_URL"] = 'redis://localhost:6379/0'
app.config["QUEUES"] = ["default"]

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
jwt = JWTManager(app)
EXPIRE = timedelta(minutes=30)


# To do: Prune the token part (done)
#        Put and Patch for new objects
#        Flask MVC


@app.route('/insert_data', methods=['POST'])
def insert_data():
    # id = request.json.get('id')
    # username = request.json.get('username')
    # password = request.json.get('password')
    #
    # body = {
    #     'id': id,
    #     'name': username,
    #     'password': password,
    #     'timestamp': datetime.now()
    # }
    #
    # result = es.index(index='contents', doc_type='title', id=id, body=body)
    es.delete(index="contents", doc_type='title', id="membercostshare:1234512xvc1314asdfs-509")

    return jsonify("deleted!"), 200


def create_task(task_type):
    time.sleep(int(task_type) * 10)
    return True


@app.route("/tasks", methods=["POST"])
def run_task():
    ## get task id
    task_type = request.json.get("id")
    ## connect to redis
    with Connection(redis.from_url(app.config["REDIS_URL"])):
        ## create the queue
        q = Queue()
        ## add to the queue
        task = q.enqueue(create_task, task_type)
    ## make responses
    response_object = {
        "status": "success",
        "data": {
            "task_id": task.get_id()
        }
    }
    return jsonify(response_object), 202


@cli.command("run_worker")
def run_worker():
    ## connect to redis
    redis_url = app.config["REDIS_URL"]
    redis_connection = redis.from_url(redis_url)
    ## start the worker
    with Connection(redis_connection):
        worker = Worker(app.config["QUEUES"])
        worker.work()


@app.route('/search', methods=['POST'])
def search():
    try:
        keyword = request.json.get('keyword')
        if keyword is None:
            return jsonify("keyword does not exist in the json input!"), 404
        else:
            res = es.get(index="contents", doc_type='title', id=keyword)
            return jsonify(res['_source'])
    except Exception as e:
        if "ConnectionError" in str(e):
            return jsonify("Connection Error! Please check if your elasticsearch is running!"), 500
        if "NotFound" in str(e):
            return jsonify("Id not found! Please double check your input!"), 404


# index
@app.route('/insert_use', methods=['POST'])
def insert_use():
    try:
        input_json = request.get_json()
        object_id = input_json.get('objectId')
        object_type = input_json.get('objectType')
        plan_cost_shares = input_json.get('planCostShares')
        linked_plan_services = input_json.get('linkedPlanServices')
        org = input_json.get('_org')
        plan_type = input_json.get('planType')
        creation_date = input_json.get('creationDate')

        # 508
        hash_root = {'planCostShares': plan_cost_shares.get('objectType') + ':' + plan_cost_shares.get('objectId'),
                     'linkedPlanServices1': linked_plan_services[0].get('objectType') + ':' + linked_plan_services[0].get(
                         'objectId'),
                     'linkedPlanServices2': linked_plan_services[1].get('objectType') + ':' + linked_plan_services[1].get(
                         'objectId'),
                     '_org': org,
                     "objectId": object_id,
                     "objectType": object_type,
                     'planType': plan_type,
                     'creationDate': creation_date
                     }
        es.index(index='contents', doc_type='title', id=object_type + ':' + object_id, body= hash_root)
        # print(org, type(org))
        linkedService1 = linked_plan_services[0]
        linkedService2 = linked_plan_services[1]
        if linkedService1.get('linkedService').get('_org') != 'example.com':
            return jsonify('please input a valid email address'), 400
        # 501
        hash_planCostShares = {
            "deductible": plan_cost_shares.get('deductible'),
            "_org": plan_cost_shares.get('_org'),
            "copay": plan_cost_shares.get('copay'),
            "objectId": plan_cost_shares.get('objectId'),
            "objectType": plan_cost_shares.get('objectType')
        }
        es.index(index='contents', doc_type='title', id=plan_cost_shares.get('objectType') + ':' + plan_cost_shares.get('objectId'), body=hash_planCostShares)
        # print(hash_planCostShares)
        # 504
        hash_linkedService1 = {
            "linkedService": linked_plan_services[0].get('linkedService').get('objectType') + ':' + linked_plan_services[
                0].get('linkedService').get('objectId'),
            "planserviceCostShares": linked_plan_services[0].get('planserviceCostShares').get('objectType') + ':' +
                                     linked_plan_services[0].get('planserviceCostShares').get('objectId'),
            "_org": linked_plan_services[0].get('_org'),
            "objectId": linked_plan_services[0].get('objectId'),
            "objectType": linked_plan_services[0].get('objectType')
        }
        # print(hash_linkedService1)
        es.index(index='contents', doc_type='title',
                 id=linked_plan_services[0].get('objectType') + ':' + linked_plan_services[0].get('objectId'),
                 body=hash_linkedService1)
        # 507
        hash_linkedService2 = {
            "linkedService": linked_plan_services[1].get('linkedService').get('objectType') + ':' + linked_plan_services[
                1].get('linkedService').get('objectId'),
            "planserviceCostShares": linked_plan_services[1].get('planserviceCostShares').get('objectType') + ':' +
                                     linked_plan_services[1].get('planserviceCostShares').get('objectId'),
            "_org": linked_plan_services[1].get('_org'),
            "objectId": linked_plan_services[1].get('objectId'),
            "objectType": linked_plan_services[1].get('objectType')
        }
        es.index(index='contents', doc_type='title',
                 id=linked_plan_services[1].get('objectType') + ':' + linked_plan_services[1].get('objectId'),
                 body=hash_linkedService2)
        # 502
        hash_11 = {
            "_org": linkedService1.get('linkedService').get('_org'),
            "objectId": linkedService1.get('linkedService').get('objectId'),
            "objectType": linkedService1.get('linkedService').get('objectType'),
            "name": linkedService1.get('linkedService').get('name')
        }
        es.index(index='contents', doc_type='title',
                 id=linkedService1.get('linkedService').get('objectType') + ':' + linkedService1.get('linkedService').get('objectId'),
                 body=hash_11)
        # 503
        hash_12 = {
            "deductible": linkedService1.get('planserviceCostShares').get('deductible'),
            "_org": linkedService1.get('planserviceCostShares').get('_org'),
            "copay": linkedService1.get('planserviceCostShares').get('copay'),
            "objectId": linkedService1.get('planserviceCostShares').get('objectId'),
            "objectType": linkedService1.get('planserviceCostShares').get('objectType')
        }
        es.index(index='contents', doc_type='title',
                 id=linkedService1.get('planserviceCostShares').get('objectType') + ':' + linkedService1.get('planserviceCostShares').get('objectId'),
                 body=hash_12)
        # 505
        hash_21 = {
            "_org": linkedService2.get('linkedService').get('_org'),
            "objectId": linkedService2.get('linkedService').get('objectId'),
            "objectType": linkedService2.get('linkedService').get('objectType'),
            "name": linkedService2.get('linkedService').get('name')
        }
        es.index(index='contents', doc_type='title',
                 id=linkedService2.get('linkedService').get('objectType') + ':' + linkedService2.get('linkedService').get('objectId'),
                 body=hash_21)
        # 506
        hash_22 = {
            "deductible": linkedService2.get('planserviceCostShares').get('deductible'),
            "_org": linkedService2.get('planserviceCostShares').get('_org'),
            "copay": linkedService2.get('planserviceCostShares').get('copay'),
            "objectId": linkedService2.get('planserviceCostShares').get('objectId'),
            "objectType": linkedService2.get('planserviceCostShares').get('objectType')
        }
        es.index(index='contents', doc_type='title',
                 id=linkedService2.get('planserviceCostShares').get('objectType') + ':' + linkedService2.get('planserviceCostShares').get('objectId'),
                 body=hash_22)

        return jsonify("successfully indexed!"), 200
    except Exception as e:
        if "ConnectionError" in str(e):
            return jsonify("Connection Error! Please check if your elasticsearch is running!"), 500


# search
@app.route('/search_use', methods=['POST'])
def seach_use():
    id = request.json.get('id')
    keyword = request.json.get('keyword')
    value = request.json.get('value')
    min = request.json.get('min')
    max = request.json.get('max')
    if id is not None:
        print("id not null")
        try:
            res = es.get(index="contents", doc_type='title', id=id)
            return jsonify(res['_source'])
        except Exception as e:
            if "ConnectionError" in str(e):
                return jsonify("Connection Error! Please check if your elasticsearch is running!"), 500
            if "NotFound" in str(e):
                return jsonify("Id not found! Please double check your input!"), 404
    elif keyword is not None:
        # body = {
        #     "query": {
        #         "multi_match": {
        #             "query": keyword,
        #             "fields": ["content", "title"]
        #         }
        #     }
        # }
        if min is not None or max is not None:
            if max is None:
                max = 0
            if min is None:
                min = 0
            body = {
                "query": {
                    "range": {
                        keyword: {
                            "gte": min,
                            "lte": max
                        }
                    }
                }
            }
            res = es.search(index="contents", doc_type='title', body=body)
            return jsonify(res['hits']['hits']), 200
        elif "*" not in value:
            body = {
                'query': {
                    'match': {
                        keyword: value
                    }
                }
            }
            # print(body)
            res = es.search(index="contents", doc_type='title', body=body)
            # print(res['hits']['hits'])
            # return jsonify("ok")
            return jsonify(res['hits']['hits']), 200
        else:
            body = {
                'query': {
                    'wildcard': {
                        keyword: value
                    }
                }
            }
            print("wildcard")
            res = es.search(index="contents", doc_type='title', body=body)
            # print(res['hits']['hits'])
            # return jsonify("ok")
            return jsonify(res['hits']['hits']), 200
    else:
        return jsonify("please check if your input makes sense"), 404
    # body = {
    #     "query": {
    #         "multi_match": {
    #             "query": keyword,
    #             "fields": ["content", "title"]
    #         }
    #     }
    # }
    #
    # res = es.search(index="contents", doc_type="title", body=body)

# Provide a method to create access tokens. The create_access_token()
# function is used to actually generate the token, and you can return
# it to the caller however you choose.
@app.route('/auth/token', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username:
        return jsonify({"msg": "Missing username parameter"}), 400
    if not password:
        return jsonify({"msg": "Missing password parameter"}), 400

    if username != 'top' or password != 'secret':
        return jsonify({"msg": "Bad username or password"}), 401

    # Identity can be any data that is json serializable
    access_token = create_access_token(identity=username, expires_delta=EXPIRE)
    ret = {
        'token': access_token,
        'expiration time': str(EXPIRE),
        'will expire at': str(datetime.now() + EXPIRE)
    }
    return jsonify(ret), 200


# A blacklisted access token will not be able to access this any more
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify({'hello': 'world'})


# put
@app.route('/put', methods=['PUT'])
@jwt_required
def put():
    input_json = request.get_json()
    object_id = input_json.get('objectId')
    es.delete(index="contents", doc_type='title', id="membercostshare:1234vxc2324sdf-501")
    es.delete(index="contents", doc_type='title', id="service:1234520xvc30asdf-502")
    es.delete(index="contents", doc_type='title', id="membercostshare:1234512xvc1314asdfs-503")
    es.delete(index="contents", doc_type='title', id="planservice:27283xvx9asdff-504")
    es.delete(index="contents", doc_type='title', id="service:1234520xvc30sfs-505")
    es.delete(index="contents", doc_type='title', id="membercostshare:1234512xvc1314sdfsd-506")
    es.delete(index="contents", doc_type='title', id="planservice:27283xvx9sdf-507")
    es.delete(index="contents", doc_type='title', id="plan:12xvxc345ssdsds-508")
    try:
        input_json = request.get_json()
        object_id = input_json.get('objectId')
        object_type = input_json.get('objectType')
        plan_cost_shares = input_json.get('planCostShares')
        linked_plan_services = input_json.get('linkedPlanServices')
        org = input_json.get('_org')
        plan_type = input_json.get('planType')
        creation_date = input_json.get('creationDate')

        # 508
        hash_root = {'planCostShares': plan_cost_shares.get('objectType') + ':' + plan_cost_shares.get('objectId'),
                     'linkedPlanServices1': linked_plan_services[0].get('objectType') + ':' + linked_plan_services[0].get(
                         'objectId'),
                     'linkedPlanServices2': linked_plan_services[1].get('objectType') + ':' + linked_plan_services[1].get(
                         'objectId'),
                     '_org': org,
                     "objectId": object_id,
                     "objectType": object_type,
                     'planType': plan_type,
                     'creationDate': creation_date
                     }
        es.index(index='contents', doc_type='title', id=object_type + ':' + object_id, body= hash_root)
        # print(org, type(org))
        linkedService1 = linked_plan_services[0]
        linkedService2 = linked_plan_services[1]
        if linkedService1.get('linkedService').get('_org') != 'example.com':
            return jsonify('please input a valid email address'), 400
        # 501
        hash_planCostShares = {
            "deductible": plan_cost_shares.get('deductible'),
            "_org": plan_cost_shares.get('_org'),
            "copay": plan_cost_shares.get('copay'),
            "objectId": plan_cost_shares.get('objectId'),
            "objectType": plan_cost_shares.get('objectType')
        }
        es.index(index='contents', doc_type='title', id=plan_cost_shares.get('objectType') + ':' + plan_cost_shares.get('objectId'), body=hash_planCostShares)
        # print(hash_planCostShares)
        # 504
        hash_linkedService1 = {
            "linkedService": linked_plan_services[0].get('linkedService').get('objectType') + ':' + linked_plan_services[
                0].get('linkedService').get('objectId'),
            "planserviceCostShares": linked_plan_services[0].get('planserviceCostShares').get('objectType') + ':' +
                                     linked_plan_services[0].get('planserviceCostShares').get('objectId'),
            "_org": linked_plan_services[0].get('_org'),
            "objectId": linked_plan_services[0].get('objectId'),
            "objectType": linked_plan_services[0].get('objectType')
        }
        # print(hash_linkedService1)
        es.index(index='contents', doc_type='title',
                 id=linked_plan_services[0].get('objectType') + ':' + linked_plan_services[0].get('objectId'),
                 body=hash_linkedService1)
        # 507
        hash_linkedService2 = {
            "linkedService": linked_plan_services[1].get('linkedService').get('objectType') + ':' + linked_plan_services[
                1].get('linkedService').get('objectId'),
            "planserviceCostShares": linked_plan_services[1].get('planserviceCostShares').get('objectType') + ':' +
                                     linked_plan_services[1].get('planserviceCostShares').get('objectId'),
            "_org": linked_plan_services[1].get('_org'),
            "objectId": linked_plan_services[1].get('objectId'),
            "objectType": linked_plan_services[1].get('objectType')
        }
        es.index(index='contents', doc_type='title',
                 id=linked_plan_services[1].get('objectType') + ':' + linked_plan_services[1].get('objectId'),
                 body=hash_linkedService2)
        # 502
        hash_11 = {
            "_org": linkedService1.get('linkedService').get('_org'),
            "objectId": linkedService1.get('linkedService').get('objectId'),
            "objectType": linkedService1.get('linkedService').get('objectType'),
            "name": linkedService1.get('linkedService').get('name')
        }
        es.index(index='contents', doc_type='title',
                 id=linkedService1.get('linkedService').get('objectType') + ':' + linkedService1.get('linkedService').get('objectId'),
                 body=hash_11)
        # 503
        hash_12 = {
            "deductible": linkedService1.get('planserviceCostShares').get('deductible'),
            "_org": linkedService1.get('planserviceCostShares').get('_org'),
            "copay": linkedService1.get('planserviceCostShares').get('copay'),
            "objectId": linkedService1.get('planserviceCostShares').get('objectId'),
            "objectType": linkedService1.get('planserviceCostShares').get('objectType')
        }
        es.index(index='contents', doc_type='title',
                 id=linkedService1.get('planserviceCostShares').get('objectType') + ':' + linkedService1.get('planserviceCostShares').get('objectId'),
                 body=hash_12)
        # 505
        hash_21 = {
            "_org": linkedService2.get('linkedService').get('_org'),
            "objectId": linkedService2.get('linkedService').get('objectId'),
            "objectType": linkedService2.get('linkedService').get('objectType'),
            "name": linkedService2.get('linkedService').get('name')
        }
        es.index(index='contents', doc_type='title',
                 id=linkedService2.get('linkedService').get('objectType') + ':' + linkedService2.get('linkedService').get('objectId'),
                 body=hash_21)
        # 506
        hash_22 = {
            "deductible": linkedService2.get('planserviceCostShares').get('deductible'),
            "_org": linkedService2.get('planserviceCostShares').get('_org'),
            "copay": linkedService2.get('planserviceCostShares').get('copay'),
            "objectId": linkedService2.get('planserviceCostShares').get('objectId'),
            "objectType": linkedService2.get('planserviceCostShares').get('objectType')
        }
        es.index(index='contents', doc_type='title',
                 id=linkedService2.get('planserviceCostShares').get('objectType') + ':' + linkedService2.get('planserviceCostShares').get('objectId'),
                 body=hash_22)

        return jsonify("updated!"), 200
    except Exception as e:
        if "ConnectionError" in str(e):
            return jsonify("Connection Error! Please check if your elasticsearch is running!"), 500
    try:
        if redis_client.exists('plan:' + object_id):
            flush_db()
            put_new_json(input_json)
            put_response = make_response(jsonify('UPDATE the json blob in the database!'), 200)
        else:
            put_response = make_response(jsonify('STORE the json blob into the database!'), 200)
        put_response.add_etag()
        final_response, sc = etag_validation(put_response)
        return final_response, sc
    except Exception as e:
        return jsonify(e), 500


def flush_db():
    redis_client.flushdb()


def etag_validation(del_response):
    old_etag = request.headers.get("If-None-Match")
    if del_response.headers['ETag'] == old_etag:
        return del_response, 304
    else:
        return del_response, 200


# patch
@app.route('/patch', methods=['PATCH'])
@jwt_required
def patch():
    input_json = request.get_json()
    object_id = input_json.get('planserviceCostShares').get('objectId')
    planserviceCostShares = input_json.get('planserviceCostShares')
    # print(input_json.get('planserviceCostShares').keys())
    hash_12 = {
        "deductible": planserviceCostShares.get('deductible'),
        "_org": planserviceCostShares.get('_org'),
        "copay": planserviceCostShares.get('copay'),
        "objectId": planserviceCostShares.get('objectId'),
        "objectType": planserviceCostShares.get('objectType')
    }
    es.index(index='contents', doc_type='title',
             id=planserviceCostShares.get('objectType') + ':' + planserviceCostShares.get('objectId'),
             body=hash_12)
    pat_response = make_response(jsonify('new object added'), 200)
    pat_response.add_etag()
    final_response, sc = etag_validation(pat_response)
    return final_response, sc
    # return jsonify("new object added"), 200
    # try:
    #     id = 'membercostshare:' + object_id
    #     if redis_client.exists('membercostshare:' + object_id):
    #         # 503
    #         value_503 = redis_client.hmget(id, [
    #             'deductible',
    #             '_org',
    #             'copay',
    #             'objectId',
    #             'objectType'])
    #         result_503 = []
    #         for o_503 in value_503:
    #             r_503 = o_503.decode('utf-8')
    #             result_503.append(r_503)
    #
    #         hash_12 = {
    #             "deductible": input_json.get('planserviceCostShares').get('deductible'),
    #             "_org": "example.com",
    #             "copay": 0,
    #             "objectId": input_json.get('planserviceCostShares').get('objectId'),
    #             "objectType": "membercostshare"
    #         }
    #         redis_client.hmset(id, hash_12)
    #         pat_response = make_response(jsonify('id: ' + str(object_id) + " Updated!"), 200)
    #     else:
    #         hash_12 = {
    #             "deductible": input_json.get('planserviceCostShares').get('deductible'),
    #             "_org": input_json.get('planserviceCostShares').get('_org'),
    #             "copay": input_json.get('planserviceCostShares').get('copay'),
    #             "objectId": input_json.get('planserviceCostShares').get('objectId'),
    #             "objectType": input_json.get('planserviceCostShares').get('objectType')
    #         }
    #         redis_client.hmset(id, hash_12)
    #         pat_response = make_response(jsonify('id: ' + str(object_id) + " Not Found!"), 404)
    #     pat_response.add_etag()
    #     final_response, sc = etag_validation(pat_response)
    #     return final_response, sc
    # except Exception as e:
    #     return jsonify(e), 500


@app.route('/')
def hello_world():
    hello_response = make_response(jsonify('Hello'), 200)
    hello_response.add_etag()
    return hello_response


# delete
@app.route('/delete', methods=['DELETE'])
@jwt_required
def delete():
    json_get = request.get_json()
    input_id = json_get.get('id')
    print(input_id)
    if input_id is None:
        flush_db()
        del_response = make_response(jsonify('database cleared!'), 200)
    else:
        if redis_client.exists(input_id):
            redis_client.delete(input_id)
            del_response = make_response(jsonify('id: ' + str(input_id) + " is deleted!"), 200)
        else:
            del_response = make_response(jsonify('id: ' + str(input_id) + " doesn't exist... Please check again"), 200)
    del_response.add_etag()
    final_response, sc = etag_validation(del_response)
    return final_response, sc


def put_new_json(input_json):
    object_id = input_json.get('objectId')
    object_type = input_json.get('objectType')
    plan_cost_shares = input_json.get('planCostShares')
    linked_plan_services = input_json.get('linkedPlanServices')
    org = input_json.get('_org')
    plan_type = input_json.get('planType')
    creation_date = input_json.get('creationDate')

    # 508
    hash_root = {'planCostShares': plan_cost_shares.get('objectType') + ':' + plan_cost_shares.get('objectId'),
                 'linkedPlanServices1': linked_plan_services[0].get('objectType') + ':' + linked_plan_services[0].get(
                     'objectId'),
                 'linkedPlanServices2': linked_plan_services[1].get('objectType') + ':' + linked_plan_services[1].get(
                     'objectId'),
                 '_org': org,
                 "objectId": object_id,
                 "objectType": object_type,
                 'planType': plan_type,
                 'creationDate': creation_date
                 }
    redis_client.hmset(object_type + ':' + object_id, hash_root)
    # print(org, type(org))
    linkedService1 = linked_plan_services[0]
    linkedService2 = linked_plan_services[1]
    if linkedService1.get('linkedService').get('_org') != 'example.com':
        return jsonify('please input a valid email address'), 400
    # 501
    hash_planCostShares = {
        "deductible": plan_cost_shares.get('deductible'),
        "_org": plan_cost_shares.get('_org'),
        "copay": plan_cost_shares.get('copay'),
        "objectId": plan_cost_shares.get('objectId'),
        "objectType": plan_cost_shares.get('objectType')
    }
    redis_client.hmset(plan_cost_shares.get('objectType') + ':' + plan_cost_shares.get('objectId'), hash_planCostShares)
    # print(hash_planCostShares)
    # 504
    hash_linkedService1 = {
        "linkedService": linked_plan_services[0].get('linkedService').get('objectType') + ':' + linked_plan_services[
            0].get('linkedService').get('objectId'),
        "planserviceCostShares": linked_plan_services[0].get('planserviceCostShares').get('objectType') + ':' +
                                 linked_plan_services[0].get('planserviceCostShares').get('objectId'),
        "_org": linked_plan_services[0].get('_org'),
        "objectId": linked_plan_services[0].get('objectId'),
        "objectType": linked_plan_services[0].get('objectType')
    }
    print(hash_linkedService1)
    redis_client.hmset(linked_plan_services[0].get('objectType') + ':' + linked_plan_services[0].get(
        'objectId'), hash_linkedService1)
    # 507
    hash_linkedService2 = {
        "linkedService": linked_plan_services[1].get('linkedService').get('objectType') + ':' + linked_plan_services[
            1].get('linkedService').get('objectId'),
        "planserviceCostShares": linked_plan_services[1].get('planserviceCostShares').get('objectType') + ':' +
                                 linked_plan_services[1].get('planserviceCostShares').get('objectId'),
        "_org": linked_plan_services[1].get('_org'),
        "objectId": linked_plan_services[1].get('objectId'),
        "objectType": linked_plan_services[1].get('objectType')
    }
    redis_client.hmset(linked_plan_services[1].get('objectType') + ':' + linked_plan_services[1].get(
        'objectId'), hash_linkedService2)
    # 502
    hash_11 = {
        "_org": linkedService1.get('linkedService').get('_org'),
        "objectId": linkedService1.get('linkedService').get('objectId'),
        "objectType": linkedService1.get('linkedService').get('objectType'),
        "name": linkedService1.get('linkedService').get('name')
    }
    redis_client.hmset(
        linkedService1.get('linkedService').get('objectType') + ':' + linkedService1.get('linkedService').get(
            'objectId'),
        hash_11)
    # 503
    hash_12 = {
        "deductible": linkedService1.get('planserviceCostShares').get('deductible'),
        "_org": linkedService1.get('planserviceCostShares').get('_org'),
        "copay": linkedService1.get('planserviceCostShares').get('copay'),
        "objectId": linkedService1.get('planserviceCostShares').get('objectId'),
        "objectType": linkedService1.get('planserviceCostShares').get('objectType')
    }
    redis_client.hmset(
        linkedService1.get('planserviceCostShares').get('objectType') + ':' + linkedService1.get(
            'planserviceCostShares').get(
            'objectId'),
        hash_12)
    # 505
    hash_21 = {
        "_org": linkedService2.get('linkedService').get('_org'),
        "objectId": linkedService2.get('linkedService').get('objectId'),
        "objectType": linkedService2.get('linkedService').get('objectType'),
        "name": linkedService2.get('linkedService').get('name')
    }
    redis_client.hmset(
        linkedService2.get('linkedService').get('objectType') + ':' + linkedService2.get('linkedService').get(
            'objectId'),
        hash_21)
    # 506
    hash_22 = {
        "deductible": linkedService2.get('planserviceCostShares').get('deductible'),
        "_org": linkedService2.get('planserviceCostShares').get('_org'),
        "copay": linkedService2.get('planserviceCostShares').get('copay'),
        "objectId": linkedService2.get('planserviceCostShares').get('objectId'),
        "objectType": linkedService2.get('planserviceCostShares').get('objectType')
    }
    redis_client.hmset(
        linkedService2.get('planserviceCostShares').get('objectType') + ':' + linkedService2.get(
            'planserviceCostShares').get(
            'objectId'),
        hash_22)


# use case post
@app.route('/post_use', methods=['POST'])
@jwt_required
def post_use():
    input_json = request.get_json()
    put_new_json(input_json)
    post_response = make_response('success!', 200)
    post_response.add_etag()
    final_response, sc = etag_validation(post_response)
    return final_response, sc


# use case get
@app.route('/get_use', methods=['GET', 'POST'])
@jwt_required
def get_use():
    try:
        # 508
        key = 'plan:12xvxc345ssdsds-508'
        value_508 = redis_client.hmget(key, [
            'planCostShares',
            'linkedPlanServices1',
            'linkedPlanServices2',
            '_org',
            "objectId",
            "objectType",
            "planType",
            'creationDate'])
        # print(type(value), value)
    except Exception as e:
        return jsonify(e), 500

    result_508 = []
    for item in value_508:
        item_new = item.decode('utf-8')
        result_508.append(item_new)

    # 501
    planCostShares = result_508[0]
    # 504
    linkedPlanServices1 = result_508[1]
    # 507
    linkedPlanServices2 = result_508[2]
    org = result_508[3]
    objectId = result_508[4]
    objectType = result_508[5]
    planType = result_508[6]
    creationDate = result_508[7]

    # 501
    value_501 = redis_client.hmget(planCostShares, [
        'deductible',
        '_org',
        'copay',
        'objectId',
        'objectType'])
    result_501 = []
    for o_501 in value_501:
        r_501 = o_501.decode('utf-8')
        result_501.append(r_501)
    # print(result_501)

    deductible_501 = result_501[0]
    _org_501 = result_501[1]
    copay_501 = result_501[2]
    objectId_501 = result_501[3]
    objectType_501 = result_501[4]

    json_501 = {
        'deductible': deductible_501,
        '_org': _org_501,
        'copay': copay_501,
        "objectId": objectId_501,
        "objectType": objectType_501,
    }

    # 504
    value_504 = redis_client.hmget(linkedPlanServices1, [
        'linkedService',
        'planserviceCostShares',
        '_org',
        "objectId",
        "objectType"])
    result_504 = unicode_list(value_504)
    linkedPlanServices_504 = result_504[0]
    planCostShares_504 = result_504[1]
    _org_504 = result_504[2]
    objectId_504 = result_504[3]
    objectType_504 = result_504[4]

    # 502
    value_502 = redis_client.hmget(linkedPlanServices_504, [
        '_org',
        'objectId',
        'objectType',
        'name'])
    result_505 = []
    for o_502 in value_502:
        r_502 = o_502.decode('utf-8')
        result_505.append(r_502)

    _org_502 = result_505[0]
    objectId_502 = result_505[1]
    objectType_502 = result_505[2]
    name_502 = result_505[3]

    json_502 = {
        '_org': _org_502,
        "objectId": objectId_502,
        "objectType": objectType_502,
        'name': name_502,
    }

    # 503
    value_503 = redis_client.hmget(planCostShares_504, [
        'deductible',
        '_org',
        'copay',
        'objectId',
        'objectType'])
    result_503 = []
    for o_503 in value_503:
        r_503 = o_503.decode('utf-8')
        result_503.append(r_503)

    deductible_503 = result_503[0]
    _org_503 = result_503[1]
    copay_503 = result_503[2]
    objectId_503 = result_503[3]
    objectType_503 = result_503[4]

    json_503 = {
        'deductible': deductible_503,
        '_org': _org_503,
        'copay': copay_503,
        "objectId": objectId_503,
        "objectType": objectType_503,
    }

    json_504 = {
        'linkedService': json_502,
        'planCostShares': json_503,
        '_org': _org_504,
        'objectId': objectId_504,
        'objectType': objectType_504}
    print(json_504)

    # 507
    value_507 = redis_client.hmget(linkedPlanServices2, [
        'linkedService',
        'planserviceCostShares',
        '_org',
        "objectId",
        "objectType"])
    result_507 = []
    for o_507 in value_507:
        r_507 = o_507.decode('utf-8')
        result_507.append(r_507)
    print(result_507)
    linkedPlanServices_507 = result_507[0]
    planCostShares_507 = result_507[1]
    _org_507 = result_507[2]
    objectId_507 = result_507[3]
    objectType_507 = result_507[4]

    # 505
    value_505 = redis_client.hmget(linkedPlanServices_507, [
        '_org',
        'objectId',
        'objectType',
        'name'])
    result_505 = []
    for o_505 in value_505:
        r_505 = o_505.decode('utf-8')
        result_505.append(r_505)

    _org_505 = result_505[0]
    objectId_505 = result_505[1]
    objectType_505 = result_505[2]
    name_505 = result_505[3]

    json_505 = {
        '_org': _org_505,
        "objectId": objectId_505,
        "objectType": objectType_505,
        'name': name_505,
    }

    # 506
    value_506 = redis_client.hmget(planCostShares_507, [
        'deductible',
        '_org',
        'copay',
        'objectId',
        'objectType'])
    print(value_506)
    result_506 = []
    for o_506 in value_506:
        r_506 = o_506.decode('utf-8')
        result_506.append(r_506)

    deductible_506 = result_506[0]
    _org_506 = result_506[1]
    copay_506 = result_506[2]
    objectId_506 = result_506[3]
    objectType_506 = result_506[4]

    json_506 = {
        'deductible': deductible_506,
        '_org': _org_506,
        'copay': copay_506,
        "objectId": objectId_506,
        "objectType": objectType_506,
    }

    json_507 = {
        'linkedService': json_505,
        'planCostShares': json_506,
        '_org': _org_507,
        'objectId': objectId_507,
        'objectType': objectType_507}
    print(json_504)

    get_response = make_response(jsonify({
        'planCostShares': json_501,
        'linkedPlanServices': [json_504, json_507],
        '_org': org,
        "objectId": objectId,
        "objectType": objectType,
        'planType': planType,
        'creationDate': creationDate,
    }),
        200)
    get_response.add_etag()
    final_response, sc = etag_validation(get_response)
    return final_response, sc


def unicode_list(input_v):
    output_v = []
    for o in input_v:
        r = o.decode('utf-8')
        output_v.append(r)
    return output_v


if __name__ == '__main__':
    app.run()
