#import copy
#from mc import *

#TODO: model MaxSequenceNumber and MaxAge

class LSA:

    def __init__(self, src, dest, msg_type, LSID, AR, seqNum, linkID, metric, isOriginatedByAttacker, isMarked, counter, isDelayedFB):
        self.src = src
        self.dest = dest
        self.type = msg_type
        self.LSID = LSID
        self.AR = AR
        self.seqNum=seqNum
        self.linkID=linkID
        self.metric=metric
        self.isOriginatedByAttacker = isOriginatedByAttacker
        self.isMarked=isMarked
        self.counter=counter
        self.isDelayedFB=isDelayedFB
        
        
        
    def printLSA(self):
        
        print '[' + str(self.LSID) + ',' + str(self.AR) + ',' + str(self.seqNum) + ',' + str(self.linkID) + ',' + str(self.isOriginatedByAttacker)  +']'
        return
        
        



class Router:

    def __init__(self, ID ):
        self.queue = []
        self.DB = []
        self.ID = ID 
        self.timer = 0
        self.isDelayedFB = False
        self.calcRT_flag = False
        self.delayedFB = []
        self.lookup_policy = 0
        
        
    def updateTimer(self):
        if self.timer>0:
            self.timer-=1
        return
    
    def addLSA(self,lsa):
        self.DB.append(lsa)
        return
    
    
    def flood(self,m,r0,r1,r2):
        
        if self.ID==1:
            if m.src == 0:
                m.dest = 2
                m.src = 1
                #send m to 2
                r2.queue.append(m)  
            elif m.src==2:
                m.dest = 0
                m.src = 1
                r0.queue.append(m) 
        
        return
    
    
    
    def FB(self,r0,r1,r2):
        
        m = self.delayedFB.pop()
        if self.ID==0:
            r1.queue.append(m)
        elif self.ID==1:
            m.src=1
            m.dest=2
            r2.queue.append(m)
        elif self.ID==2:
            m.src=2
            m.dest=1
            r1.queue.append(m)
            
        
        return
    
    def RTCalc(self):
        reachables = [False]*routers_num
        if self.calcRT_flag:
            v = self.ID
            #handle router LSAs
            found = False
            for lsa in self.DB:
                if lsa.type=='routerLSA' and lsa.LSID==v:
                    found=True
                    break
            if found:
                #default database lookup
                index = 0
                delta=1
                if  self.lookup_policy==1:
                    index = len(self.DB)-1
                    delta=-1
                foundLSA=self.DB[0]
                for m in self.DB:
                    currlsa = self.DB[index]
                    if currlsa.LSID==v:
                        foundLSA=currlsa
                        break
                    index = index + delta
                
#                 index=0
#                 foundLSA=self.DB[0]                              
#                 for lsa in self.DB: #TODO: arbitrary order
#                     if lsa.LSID==v:
#                         foundLSA=lsa
#                         break
#                     index+=1
                if foundLSA.type=='routerLSA' and foundLSA.LSID==v:
                    w = foundLSA.linkID
                    w_index=0
                    delta=1
                    if self.lookup_policy==1:
                        w_index = len(self.DB)-1
                        delta=-1
                    for m in self.DB:
                        lsa = self.DB[w_index]
                        if lsa.LSID==w and lsa.linkID==v and lsa.type=='routerLSA':
                            foundLSA.isMarked=True
                            self.DB[w_index].isMarked=True
                            reachables[w]=True
                        w_index = w_index + delta
                        
#                     w_index=0
#                     for lsa in self.DB:
#                         if lsa.LSID==w and lsa.linkID==v and lsa.type=='routerLSA':
#                             foundLSA.isMarked=True
#                             self.DB[w_index].isMarked=True
#                             reachables[w]=True
#                         w_index+=1
                            
            for lsa in self.DB:
                if lsa.type=='summaryLSA' and reachables[lsa.AR]:
                    lsa.isMarked=True
                    
            self.calcRT_flag=False            
                
        
        
        return
    
    def handelLSAMsg(self,m,r0,r1,r2):
        #assume: m.type = 'routerLSA' or 'summaryLSA'
        #assume: m.src = 0 or 2 //valid neighbor
        
        #search for such LSA in DB
        found = False
        isGreaterSeqNum = False
        prevCounter=0
        prevIsFake=False
        index = 0
        for lsa in self.DB:
            if lsa.LSID == m.LSID and lsa.AR ==m.AR and lsa.type==m.type :
                found = True
                if m.seqNum > lsa.seqNum :
                    isGreaterSeqNum = True
                prevCounter = lsa.counter
                prevIsFake = lsa.isOriginatedByAttacker 
                break
            index+=1
        
        if found==False or isGreaterSeqNum==True :  #LSA is newer than one in LSDB
            
            #flood m
            self.flood(m,r0,r1,r2)            
            
            if found==False:
                #add m to the DB
                self.DB.append(m)
                
            if m.AR == self.ID : #self-originated
                self.timer = MINLSINTERVAL
                #generate fight-back LSA
                #FB = copy.deepcopy(m)
                FBM = LSA(m.src, m.dest, m.type, m.LSID, m.AR, (m.seqNum)+1, m.linkID, m.metric, False, False, 0, True)
                #FB=m 
                #FB.seqNum = m.seqNum + 1;
                #FB.isOriginatedByAttacker = False; 
                #FB.isDelayedFB = True; 
                #setDBEntry(idNum, i ,  FB );
                self.DB[index]=FBM
                
                
                #store fight-back LSA
                self.delayedFB.append(FBM)
                self.isDelayedFB=True
                
            
            else:
                if prevIsFake and m.isOriginatedByAttacker:  #counting consecutive occurrences of fake msgs in LSDB
                    m.counter=prevCounter
                else:
                    m.counter=0                
                self.DB[index]=m #update LSDB with the new LSA 
                
                self.calcRT_flag=True
                

        
        return
    
    def processRouterMessage(self,r0,r1,r2):
        #update counters in DB  --counters are calculated only for attacker's msgs
        for lsa in self.DB:
            if lsa.isOriginatedByAttacker :
                lsa.counter = lsa.counter+1
        
        #check if there is a message to process
        if len(self.queue) >0 :
            m = self.queue.pop(0) #TODO check
            if m.dest != self.ID :
                m.src = self.ID
                #get next hop
                nextHop=0
                if self.ID==1 :
                    if m.dest==0 :
                        nextHop = 0
                    else:
                        nextHop=2
                    
                elif self.ID==2 :
                    if m.dest<2 :
                        nextHop = 1
                    else:
                        nextHop=3
                    
                #send m to next hop
                if nextHop==1:
                    r1.addLSA(m) #TODO check
                elif nextHop==2:
                    r2.addLSA(m) #TODO check
            else:
                #handle lsa msg
                self.handelLSAMsg(m,r0,r1,r2)
            
            
        
        #handle delayed FB    
        if self.timer==0 and self.isDelayedFB==True:
            self.FB(r0,r1,r2)
            self.timer = MINLSINTERVAL
            self.isDelayedFB=False
        
        
        #RT calculation 
        self.RTCalc()
            
        return            
                    
                
                
#def modelAttackerBehavior(seq1,seq2):    
    #(self, src, dest, msg_type, LSID, AR, seqNum, linkID, metric, isOriginatedByAttacker, isMarked, counter, isDelayedFB):
    

    
    #--------------------------------------------------------------
    
    #trigger and disguised LSA attack:
    #lsa = LSA(0,1,'routerLSA',2,2,1,1,2,True,False,0,False)
    #r1.queue.append(lsa)
    #lsa = LSA(0,1,'routerLSA',2,2,2,1,2,True,False,0,False)
    #r1.queue.append(lsa)
    #return 


MINLSINTERVAL = 2    
routers_num = 3
attacker = 0
min_counter=10
loop_bound=15
#timers = [0]*routers_num
#calcRT_flag = [False]*routers_num
#isDelayedFB = [False]*routers_num




def runModel(x,y,z,w):
    
    r0 = Router(0)
    r1 = Router(1)
    r2 = Router(2)
    
    r1.lookup_policy = 1
    r2.lookup_policy = 1
    
    
    #init_DBs()
    lsa1 = LSA('NA','NA','routerLSA',1,1,0,2,1,False,True,0,False)
    lsa2 = LSA('NA','NA','routerLSA',2,2,0,1,1,False,True,0,False)
    
    r1.addLSA(lsa1)
    r1.addLSA(lsa2)
    
    r2.addLSA(lsa2)
    r2.addLSA(lsa1)

    for k in range(0,loop_bound):
        r0.processRouterMessage(r0,r1,r2)
        r1.processRouterMessage(r0,r1,r2)
        r2.processRouterMessage(r0,r1,r2)
        
        if k==0:
            #modelAttackerBehavior(x,y)
            #send msg with abstract seqNum
            #( src, dest, msg_type, LSID, AR, seqNum, linkID, metric, isOriginatedByAttacker, isMarked, counter, isDelayedFB):
            #lsa = LSA(0,1,'routerLSA',2,2,x,1,2,True,False,0,False)
            #r1.queue.append(lsa)
            #lsa1 = LSA(0,1,'routerLSA',2,2,y,1,2,True,False,0,False)
            #r1.queue.append(lsa1)
            
            #lsa = LSA(0,1,'routerLSA',y,z,x,w,2,True,False,0,False)
            #r1.queue.append(lsa)
            lsa = LSA(0,1,'routerLSA',2,0,1,1,2,True,False,0,False)
            r1.queue.append(lsa)
            #src, dest, msg_type, LSID, AR, seqNum, linkID, metric, isOriginatedByAttacker, isMarked, counter, isDelayedFB
        
        r0.updateTimer()
        r1.updateTimer()
        r2.updateTimer()
    


    #noFakeLSA = True
        
    for lsa in r1.DB:
        lsa.printLSA()
        if lsa.isOriginatedByAttacker and lsa.isMarked and lsa.counter>min_counter:            
            print "fake lsa "
                
    for lsa in r2.DB:
        lsa.printLSA()
        if lsa.isOriginatedByAttacker and lsa.isMarked and lsa.counter>min_counter:            
            print "fake lsa "              
    
    print "done"
    
    return


runModel(0,0,0,0)

#runModel(x)

# x = BitVec("x", 4)
# y = BitVec("y", 4)
# z = BitVec("z", 4)
# w = BitVec("w", 4)
# #mc_fuzz(lambda: runModel(x,y), [x,y], [0,0])
# #mc_fuzz(lambda: runModel(x), [x], [0])
# mc_fuzz(lambda: runModel(x,y,z,w), [x,y,z,w], [0,0,0,0])

#runModel(7,2)    