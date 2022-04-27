/*jshint -W033 */
const events = require('events');
const {BluetoothHciSocket} = require (`../build/Release/bluetooth_hci_socket.node`);


inherits(BluetoothHciSocket, events.EventEmitter);

class BluetoothHciSocketWrapped extends BluetoothHciSocket {
  constructor(debug = false) {
    super();
    this._done = false
    this._queued = []
    this._executing = false
    this.prepare(debug)
  }

  get executing() {
    return this._executing
  }

  _emitData(data){
    this.emit('predata', data)
    this._disconnectWorkaroundOnData(data, ()=>{
      this.emit('data', data)
    })
  }

  _disconnectWorkaroundOnData(data, fn){    
    if(this._done) throw new Error(`Socket closed, can't write`);
    const doFn = ()=>{
      super.kernelDisconnectWorkArounds(data, (err)=>{
        if(err) this.emit('error', err)
        try {
          fn()
        } finally {
          this._doFn()
        }
      })
    }
    if(this._executing){
      this._queued.push(doFn)
    }else{
      this._executing = true
      doFn()
    }
    
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
      const doFn = ()=>{
        super.write(data, (err)=>{
          if(err) {
            this.emit('error', err)
            reject(err)
          }
          resolve()
          this._doFn()
        })
      }

      if(this._executing){
        this._queued.push(doFn)
      }else{
        this._executing = true
        doFn()
      }
    })
  }

  async cleanup(){
    return await new Promise((resolve, reject)=>{
      const doFn = ()=>{
        super.cleanup((err)=>{
          if(err) {
            this.emit('error', err)
            reject(err)
          }
          resolve()
          this._doFn()
        })
      }

      if(this._executing){
        this._queued.push(doFn)
      }else{
        this._executing = true
        doFn()
      }
    })
  }

  _doFn(){
    const q = this._queued.shift()
    if(q){
      q()
    }else{
      this._executing = false
    }
  }
}

// extend prototype
function inherits(target, source) {
  for (var k in source.prototype) {
    target.prototype[k] = source.prototype[k];
  }
}

module.exports = BluetoothHciSocketWrapped;
