const Q = require('q-lite'),
      ExecutionQueue = require('../lib/ExecutionQueue'),
      {expect} = require('chai')

describe('Execution Queue', function(){
    it('should queue work', async function(){
        const queue = new ExecutionQueue()
        let state = false, secondRun
        queue.run(async (d)=>{
            await Q.delay(50)
            if(state === false) state = true
            d()
        })
        queue.run(()=>{
            if(state == false) state = 'error'
            secondRun = true
        })
        
        await Q.delay(100)

        expect(state).to.be.true
        expect(secondRun).to.be.true
    })
    it('should queue work even after exception', async function(){
        const queue = new ExecutionQueue()
        let state = false, secondRun
        queue.run((d)=>{
            state = true
            throw new Error('test')
        }).catch(ex=>{
            // expected
        })
        queue.run(()=>{
            if(state == false) state = 'error'
            secondRun = true
        })
        

        expect(state).to.be.true
        expect(secondRun).to.be.true
    })
})