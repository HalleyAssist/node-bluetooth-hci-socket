/*jshint -W033 */
const events = require('events'),
     {BluetoothHciSocket} = require (`../build/Release/bluetooth_hci_socket.node`),
     ExecutionQueue = require('./ExecutionQueue')


inherits(BluetoothHciSocket, events.EventEmitter);

class BluetoothHciSocketWrapped extends BluetoothHciSocket {
  constructor(debug = false) {
    super();
    this._done = false
    this.prepare(debug)
    this._queue = new ExecutionQueue()
  }

  get executing() {
    return this._queue.executing
  }
  get queueLength(){
    return this._queue.queueLength
  }

  _emitData(data){
    this.emit('predata', data)
    this._disconnectWorkaroundOnData(data, ()=>{
      this.emit('data', data)
    })
  }

  _disconnectWorkaroundOnData(data, fn){    
    if(this._done) throw new Error(`Socket closed, can't write`);
    const doFn = (done)=>{
      super.kernelDisconnectWorkArounds(data, (err)=>{
        if(err) this.emit('error', err)
        try {
          fn()
        } finally {
          done()
        }
      })
    }

    this._queue.run(doFn)    
  }

  start(){
    // Every minute perform a cleanup of connecting devices
    this._timer = setInterval(async ()=>{
      try {
        await this.cleanup();
      } catch(ex){
        // Ingore
      }
    }, 60 * 1000);
    this._timer.unref();
    return super.start();
  }

  stop(){
    this._done = true
    clearInterval(this._timer);
    return super.stop();
  }

 async write(data){
    if(this._done) throw new Error(`Socket closed, can't write`);
    return await new Promise((resolve, reject)=>{
      const doFn = done=>{
        super.kernelConnectWorkArounds(data, err=>{
          if(err) {
            if(err.message == "connect failed (undefined)"){
              this.emit('connectFailed', data)
            }
          }
        })
        super.write(data, (err)=>{
          if(err) {
            this.emit('error', err)
            reject(err)
          } else {
            resolve()
          }
          done()
        })
      }

      this._queue.run(doFn)    
    })
  }

  async cleanup(){
    return await new Promise((resolve, reject)=>{
      const doFn = done=>{
        super.cleanup((err)=>{
          if(err) {
            this.emit('error', err)
            reject(err)
          } else {
            resolve()
          }
          done()
        })
      }
      
      this._queue.run(doFn)    
    })
  }
}

// extend prototype
function inherits(target, source) {
  for (var k in source.prototype) {
    target.prototype[k] = source.prototype[k];
  }
}

module.exports = BluetoothHciSocketWrapped;
