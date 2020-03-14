import redis
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, make_response
from flask_redis import FlaskRedis
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token, get_jti,
    jwt_refresh_token_required, get_jwt_identity, jwt_required, get_raw_jwt
)

REDIS_URL = "redis://localhost:6379/0"

app = Flask(__name__)
redis_client = FlaskRedis(app)
app.config['JSON_SORT_KEYS'] = False
app.secret_key = 'ChangeMe!'

# Setup the flask-jwt-extended extension. See:
ACCESS_EXPIRES = timedelta(minutes=15)
REFRESH_EXPIRES = timedelta(days=30)
EXPIRE = timedelta(minutes=10)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = ACCESS_EXPIRES
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = REFRESH_EXPIRES
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
jwt = JWTManager(app)

# Setup our redis connection for storing the blacklisted tokens
revoked_store = redis.StrictRedis(host='localhost', port=6379, db=0,
                                  decode_responses=True)


# To do: Prune the token part
#        Put and Patch for new objects
#        Flask MVC



# Create our function to check if a token has been blacklisted. In this simple
# case, we will just store the tokens jti (unique identifier) in redis
# whenever we create a new token (with the revoked status being 'false'). This
# function will return the revoked status of a token. If a token doesn't
# exist in this store, we don't know where it came from (as we are adding newly
# created tokens to our store with a revoked status of 'false'). In this case
# we will consider the token to be revoked, for safety purposes.
@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(decrypted_token):
    jti = decrypted_token['jti']
    entry = revoked_store.get(jti)
    if entry is None:
        return True
    return entry == 'true'


@app.route('/auth/token', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    # token = request.headers.get("Authorization")
    # print(token)
    if username != 'top' or password != 'secret':
        return jsonify({"msg": "Wrong username or password"}), 401

    # Create our JWTs
    access_token = create_access_token(identity=username, expires_delta=EXPIRE)
    refresh_token = create_refresh_token(identity=username)

    # Store the tokens in redis with a status of not currently revoked. We
    # can use the `get_jti()` method to get the unique identifier string for
    # each token. We can also set an expires time on these tokens in redis,
    # so they will get automatically removed after they expire. We will set
    # everything to be automatically removed shortly after the token expires
    access_jti = get_jti(encoded_token=access_token)
    refresh_jti = get_jti(encoded_token=refresh_token)
    revoked_store.set(access_jti, 'false', ACCESS_EXPIRES * 1.2)
    revoked_store.set(refresh_jti, 'false', REFRESH_EXPIRES * 1.2)

    ret = {
        'token': access_token,
        # 'refresh_token': refresh_token,
        'expiration time': str(EXPIRE),
        'will expire at': str(datetime.now() + EXPIRE)
    }
    return jsonify(ret), 201


# A blacklisted access token will not be able to access this any more
@app.route('/protected', methods=['GET'])
@jwt_required
def protected():
    return jsonify({'hello': 'world'})


# A blacklisted refresh tokens will not be able to access this endpoint
@app.route('/auth/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    # Do the same thing that we did in the login endpoint here
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    access_jti = get_jti(encoded_token=access_token)
    revoked_store.set(access_jti, 'false', ACCESS_EXPIRES * 1.2)
    ret = {'access_token': access_token}
    return jsonify(ret), 201


# Endpoint for revoking the current users access token
@app.route('/auth/access_revoke', methods=['DELETE'])
@jwt_required
def logout():
    jti = get_raw_jwt()['jti']
    revoked_store.set(jti, 'true', ACCESS_EXPIRES * 1.2)
    return jsonify({"msg": "Access token revoked"}), 200


# Endpoint for revoking the current users refresh token
@app.route('/auth/refresh_revoke', methods=['DELETE'])
@jwt_refresh_token_required
def logout2():
    jti = get_raw_jwt()['jti']
    revoked_store.set(jti, 'true', REFRESH_EXPIRES * 1.2)
    return jsonify({"msg": "Refresh token revoked"}), 200


# put
@app.route('/put', methods=['PUT'])
@jwt_required
def put():
    input_json = request.get_json()
    object_id = input_json.get('objectId')
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
    # print(input_json.get('planserviceCostShares').keys())
    try:
        id = 'membercostshare:' + object_id
        if redis_client.exists('membercostshare:' + object_id):
            # 503
            value_503 = redis_client.hmget(id, [
                'deductible',
                '_org',
                'copay',
                'objectId',
                'objectType'])
            result_503 = []
            for o_503 in value_503:
                r_503 = o_503.decode('utf-8')
                result_503.append(r_503)

            hash_12 = {
                "deductible": input_json.get('planserviceCostShares').get('deductible'),
                "_org": "example.com",
                "copay": 0,
                "objectId": input_json.get('planserviceCostShares').get('objectId'),
                "objectType": "membercostshare"
            }
            redis_client.hmset(id, hash_12)
            pat_response = make_response(jsonify('id: ' + str(object_id) + " Updated!"), 200)
        else:
            hash_12 = {
                "deductible": input_json.get('planserviceCostShares').get('deductible'),
                "_org": input_json.get('planserviceCostShares').get('_org'),
                "copay": input_json.get('planserviceCostShares').get('copay'),
                "objectId": input_json.get('planserviceCostShares').get('objectId'),
                "objectType": input_json.get('planserviceCostShares').get('objectType')
            }
            redis_client.hmset(id, hash_12)
            pat_response = make_response(jsonify('id: ' + str(object_id) + " Not Found!"), 404)
        pat_response.add_etag()
        final_response, sc = etag_validation(pat_response)
        return final_response, sc
    except Exception as e:
        return jsonify(e), 500


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
    print(org, type(org))
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
    # try:
    #     key = request.args['id']
    # except Exception as e:
    #     return jsonify('Please check if \'id\' exists in the request'), 500
    # # print(key, type(key))
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
    # result_507 = []
    # for o_504 in value_507:
    #     r_504 = o_504.decode('utf-8')
    #     result_507.append(r_504)
    # print(result_507)
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
