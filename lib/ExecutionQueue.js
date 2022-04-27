class ExecutionQueue {
    constructor(){
        this._queued = []
        this._executing = false
    }

    get executing() {
        return this._executing
    }

    get queueLength(){
        return this._queued.length
    }

    _onceDone(){
        let called = false
        return ()=>{
            if(called) return
            called = true
            this._handleDone()
        }
    }

    async _handleDone(){
        const q = this._queued.shift()
        if(q){
            const od = this._onceDone()
            try {
                q.resolve(q.fn(od))
            } catch(ex){
                od()
                q.reject(ex)
            }
        }else{
            this._executing = false
        }
    }

    async run(fn){
        let resolve, reject
        const p = new Promise((_resolve, _reject)=>{
            resolve = _resolve
            reject = _reject
        })
        if(this._executing){
            this._queued.push({fn, resolve, reject})
        } else {
            this._executing = true
            const od = this._onceDone()
            try {
                resolve(fn(od))
            } catch(ex){
                od()
                reject(ex)
            }
        }
        return p
    }
}

module.exports = ExecutionQueue