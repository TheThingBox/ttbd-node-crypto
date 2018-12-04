module.exports = function(RED) {
  const path = require('path')
  const fs = require('fs');
  const { execFile } = require('child_process');
  const ttb_crypto_bin_path = path.join('/usr/local/bin', 'ttb-crypto');
  const default_pub_key_path = '/root/certs/my-ttb.pub'
  const mythingbox_pub_key_path = '/root/certs/serv.pub'
  const default_priv_key_path = '/root/certs/my-ttb.key.pem'

  const cmdOpt = {
    encoding: 'utf8',
    timeout: 0,
    maxBuffer: 200 * 1024,
    killSignal: 'SIGTERM',
    cwd: null,
    env: null
  }

  function isObject(val) {
    if (val === null) { return false;}
    return ( (typeof val === 'function') || (typeof val === 'object') );
  }

  function ttbCrypto(n) {
    RED.nodes.createNode(this,n);
    this.param = {
      action: n.action,
      actionType: n.actionType,
      algo: n.algo,
      algoType: n.algoType,
      pubKey: n.pubKey,
      pubKeyType: n.pubKeyType,
      privKey: n.privKey,
      privKeyType: n.privKeyType
    }

    if (this.param.actionType === "cipherAction") {
      this.param.action = 'cipher'
    }

    if (this.param.actionType === "decipherAction") {
      this.param.action = 'decipher'
    }

    if (this.param.algoType === "rsa-aes-256-gcmAlgo") {
      this.param.algo = 'aes-256-gcm'
    }

    if (this.param.pubKeyType === "defaultPubKey") {
      this.param.pubKey = default_pub_key_path
    } else if (this.param.pubKeyType === "mythingboxPubKey") {
      this.param.pubKey = mythingbox_pub_key_path
    }

    if (this.param.privKeyType === "defaultPrivKey") {
      this.param.privKey = default_priv_key_path
    }

    this.name = n.name;
    var node = this;

    this.on('input', function(msg) {
      action = node.param.action
      algo = node.param.algo
      pubKey = node.param.pubKey
      privKey = node.param.privKey

      if(node.param.actionType === "setAction") {
        try {
            action = RED.util.getMessageProperty(msg, 'action');
        } catch (err) {}
        if(!action){
          node.warn("msg.action is undefined");
        }
      } else if(node.param.actionType === "msg"){
        try {
            action = RED.util.getMessageProperty(msg, node.param.action);
        } catch (err) {}
        if(!action){
          node.warn("msg." + node.param.actionType + " is undefined");
        }
      }
      if(!action){
        return
      }

      var _action = null
      if(action.toLowerCase() === 'cipher' || action.toLowerCase() === 'cypher'){
        _action = 'encrypt'
      } else if(action.toLowerCase() === 'decipher' || action.toLowerCase() === 'decypher'){
        _action = 'decrypt'
      }

      if(!_action){
        node.warn('Unknown action ' +action+ ' sould set to "cipher" or to "decipher"')
        return
      }

      if(node.param.pubKeyType === "setPubKey") {
        try {
            pubKey = RED.util.getMessageProperty(msg, 'publicKey');
        } catch (err) {}
        if(!pubKey){
          node.warn("msg.publicKey is undefined");
        }
      } else if(node.param.pubKeyType === "msg"){
        try {
            pubKey = RED.util.getMessageProperty(msg, node.param.pubKey);
        } catch (err) {}
        if(!pubKey){
          node.warn("msg." + node.param.pubKeyType + " is undefined");
        }
      }
      if(!pubKey){
        return
      } else if(!fs.existsSync(pubKey)){
        node.warn("Cannot find the public key at "+pubKey)
        return
      }

      if(node.param.privKeyType === "setPrivKey") {
        try {
            privKey = RED.util.getMessageProperty(msg, 'privateKey');
        } catch (err) {}
        if(!privKey){
          node.warn("msg.privateKey is undefined");
        }
      } else if(node.param.privKeyType === "msg"){
        try {
            privKey = RED.util.getMessageProperty(msg, node.param.privKey);
        } catch (err) {}
        if(!privKey){
          node.warn("msg." + node.param.privKeyType + " is undefined");
        }
      }
      if(!privKey){
        return
      } else if(!fs.existsSync(privKey)){
        node.warn("Cannot find the private key at "+privKey)
        return
      }

      var payload = msg.payload
      if(Buffer.isBuffer(payload)){
        payload = payload.toString()
      } else if (isObject(payload)) {
        payload = JSON.stringify(payload);
      } else if (typeof payload !== "string") {
        payload = "" + payload;
      }
      const cmdEncrypt = [
        `-action=${_action}`,
        `-algo=${algo}`,
        `-private_key=${privKey}`,
        `-public_key=${pubKey}`,
        `-text=${payload}`
      ]
      execFile(ttb_crypto_bin_path, cmdEncrypt, cmdOpt, (error, stdout, stderr) => {
        if(error){
          msg.error = error
          node.send(msg)
          return
        }
        if(stdout){
          msg.payload = stdout
          if(_action === 'decrypt'){
            msg.signature = true
          }
          msg.error = undefined
        }
        if(stderr){
          msg.error = stderr
          if(_action === 'decrypt'){
            msg.signature = undefined
          }
          if(msg.error === 'Bad signature'){
            msg.error = undefined
            msg.signature = false
          } else {
            msg.payload = undefined
          }
        }
        node.send(msg)
      });
    })
  }

  RED.nodes.registerType("ttb-crypto", ttbCrypto);
}
