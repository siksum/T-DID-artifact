from pathlib import Path
import importlib.util, json, shutil
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

ROOT=Path(__file__).resolve().parent
OUT=ROOT.parent/'figures'; OUT.mkdir(exist_ok=True)
NAVY,TEAL,GRAY='#263B53','#438F88','#697783'
plt.rcParams.update({'font.family':'STIXGeneral','font.size':9,'pdf.fonttype':42,'svg.fonttype':'none'})
# Fixed creation date and SVG ids: regenerated figures are byte-identical to the released files.
plt.rcParams['svg.hashsalt']='tdid'
META={'svg':{'Date':None},'pdf':{'CreationDate':None},'png':{}}
def canvas(h):
 f,a=plt.subplots(figsize=(7.16,h));a.set(xlim=(0,1),ylim=(0,1));a.axis('off');f.subplots_adjust(0,0,1,1);return f,a
def box(a,x,y,w,h,text,fill='white',size=9):
 a.add_patch(FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.007,rounding_size=0.015',facecolor=fill,edgecolor=NAVY,lw=.9))
 a.text(x+w/2,y+h/2,text,ha='center',va='center',fontsize=size,color=NAVY,linespacing=1.2)
def arrow(a,start,end,label='',pos=None,color=TEAL,style='-'):
 a.add_patch(FancyArrowPatch(start,end,arrowstyle='-|>',mutation_scale=9,lw=1.05,color=color,linestyle=style))
 if label:
  x,y=pos if pos else ((start[0]+end[0])/2,(start[1]+end[1])/2+.035)
  a.text(x,y,label,ha='center',va='center',fontsize=8,color=color)
def save(f,n):
 for ext in ['svg','pdf','png']:f.savefig(OUT/f'Fig{n}.{ext}',dpi=360,metadata=META[ext])
 plt.close(f)

f,a=canvas(2.55)
boxes=[(.025,.42,.17,.25,'Six DID/VC\nspecifications'),(.245,.42,.19,.25,'Threat catalog\n21 threats\nSuccess conditions'),(.485,.42,.21,.25,'Security logging\nFields · producers · links'),(.755,.42,.22,.25,'Stateful adjudication\nSuccess · no success\n· incomplete')]
for x,y,w,h,t in boxes:box(a,x,y,w,h,t,fill='#F3F6F8')
for l,r in zip(boxes,boxes[1:]):arrow(a,(l[0]+l[2]+.005,.545),(r[0]-.008,.545))
box(a,.245,.08,.19,.18,'ATT&CK · AADAPT\nCAPEC · CWE',size=8.5)
arrow(a,(.34,.413),(.34,.268),'Correspondence',(.455,.30),color=GRAY,style='--')
box(a,.775,.79,.18,.15,'Execution records',size=8.5)
arrow(a,(.865,.782),(.865,.678))
save(f,1)

f,a=canvas(3.45)
box(a,.018,.30,.18,.56,'DID/VC producers\n\nIssuer · Wallet\nVerifier\nRelying application\nResolver · Status service',size=8.5)
box(a,.255,.64,.16,.22,'Collection /\nnormalization\nNative + added records',fill='#F3F6F8',size=8.5)
box(a,.465,.64,.16,.22,'Input validation\nSchema · source\nsequence · integrity',fill='#F3F6F8',size=8.5)
box(a,.68,.64,.15,.22,'Event correlation\n+ prior history',fill='#F3F6F8',size=8.5)
box(a,.855,.64,.13,.22,'Rule\nevaluation',fill='#EDF5F3',size=9)
arrow(a,(.205,.75),(.247,.75))
arrow(a,(.422,.75),(.457,.75))
arrow(a,(.632,.75),(.672,.75))
arrow(a,(.837,.75),(.847,.75))
box(a,.68,.18,.15,.18,'Prior state\nRead before evaluation\nCommit after evaluation',size=7.5)
arrow(a,(.755,.367),(.755,.632),'Read',(.70,.49))
# Evaluation completes before deltas become visible to the next event.
a.plot([.885,.885,.80],[.632,.44,.44],color=TEAL,lw=1.05)
arrow(a,(.80,.44),(.80,.367))
box(a,.855,.03,.13,.20,'Verdict\nEvidence IDs\nUnknown conditions',fill='#EDF5F3',size=8)
arrow(a,(.975,.632),(.975,.238))
box(a,.255,.18,.37,.18,'Event schema · producer registry',size=8.5)
arrow(a,(.545,.367),(.545,.632),color=GRAY,style='--')
a.text(.255,.05,'Solid: records / state flow     Dashed: configuration',fontsize=8,color=GRAY)
save(f,2)

