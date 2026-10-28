"""Frozen observations -> publication figures. No detector or experimental code runs."""
from pathlib import Path
import csv, json, hashlib
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import MultipleLocator

ROOT=Path(__file__).resolve().parent
DATA=ROOT.parent/'data/figures'; OUT=ROOT.parent/'figures'; OUT.mkdir(exist_ok=True)
NAVY,TEAL,SLATE,WARM='#263B53','#438F88','#8494A4','#A88262'
STYLES=[('pltl','PLTL',SLATE,'s'),('ltl3','LTL3',NAVY,'^'),
        ('fo','MonPoly',WARM,'D'),('tdid_all','T-DID (21 rules)',TEAL,'o')]
plt.rcParams.update({'font.family':'STIXGeneral','font.size':9,'axes.labelsize':9,
 'legend.fontsize':8,'xtick.labelsize':8,'ytick.labelsize':8,
 'pdf.fonttype':42,'ps.fonttype':42,'svg.fonttype':'none',
 'axes.spines.top':False,'axes.spines.right':False,'axes.linewidth':.6,
 'axes.edgecolor':'#444444','text.color':'#20252A','axes.labelcolor':'#20252A',
 'xtick.major.width':.5,'ytick.major.width':.5,'xtick.major.size':3,'ytick.major.size':3,
 'figure.facecolor':'white','axes.facecolor':'white','savefig.facecolor':'white'})
# Fixed creation date and SVG ids: regenerated figures are byte-identical to the released files.
plt.rcParams['svg.hashsalt']='tdid'
META={'svg':{'Date':None},'pdf':{'CreationDate':None},'png':{}}
CHECKS={}; plotted=[]

def readcsv(path):return list(csv.DictReader(path.open()))
def outcsv(path,rows):
 with path.open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def grid(ax):
 ax.grid(axis='y',color='#DFE3E6',lw=.45);ax.set_axisbelow(True)
def save(fig,name):
 # Fixed 7.16in canvas: exporting does not silently shrink labels via tight bounding boxes.
 for ext in ['pdf','svg','png']:
  fig.savefig(OUT/f'{name}.{ext}',dpi=360,metadata=META[ext])
 plt.close(fig)
def legend(ax,handles,labels,cols=1,y=-.29,**kw):
 return ax.legend(handles,labels,loc='upper center',bbox_to_anchor=(.5,y),
  ncol=cols,frameon=False,handlelength=1.6,handletextpad=.5,
  columnspacing=1.1,borderaxespad=0,labelspacing=.3,**kw)

def missing():
 d=json.loads((DATA/'fig2.json').read_text()); x=np.array(d['ps'])
 assert d['workflows']==39
 for metric in ['wrong','withheld']:
  for agg in ['mean','min','max']:assert np.allclose(d[metric]['pltl'][agg],d[metric]['fo'][agg])
 for agg in ['mean','min','max']:
  assert np.allclose(d['attacks']['pltl']['detected'][agg],d['attacks']['fo']['detected'][agg])
  assert np.allclose(d['attacks']['pltl']['detected'][agg],d['attacks']['ltl3']['detected'][agg])
 fig,axs=plt.subplots(1,3,figsize=(7.16,2.85))
 fig.subplots_adjust(left=.065,right=.985,bottom=.36,top=.975,wspace=.37)
 configs=[('wrong','Wrong verdicts (%)',25,[0,5,10,15,20,25],
  [('pltl','PLTL / MonPoly',SLATE,'s','--'),('ltl3','LTL3',NAVY,'^',':'),('tdid','T-DID',TEAL,'o','-')]),
  ('withheld','Incomplete (%)',100,[0,25,50,75,100],
  [('pltl','PLTL / MonPoly',SLATE,'s','--'),('ltl3','LTL3',NAVY,'^',':'),('tdid','T-DID',TEAL,'o','-')]),
  ('detected','Attack detection (%)',100,[0,25,50,75,100],
  [('pltl','PLTL / LTL3 / MonPoly',SLATE,'s','--'),('tdid','T-DID',TEAL,'o','-')])]
 for ax,(metric,ylabel,top,ticks,series),letter in zip(axs,configs,'abc'):
  for key,label,color,marker,ls in series:
   values=d['attacks'][key]['detected'] if metric=='detected' else d[metric][key]
   y=np.array(values['mean'])
   marker_indices=list(range(len(x)))
   if metric=='withheld' and key=='ltl3':marker_indices=[0,2,4,6,8,10]
   if metric=='withheld' and key=='tdid':marker_indices=[0,1,3,5,7,9]
   ax.plot(x,y,color=color,marker=marker,mfc='white',mew=.9,ms=3.7,lw=1.25,ls=ls,
     markevery=marker_indices,label=label,clip_on=False)
   for i,v in enumerate(x):
    plotted.append(dict(figure='Fig3',panel=metric,series=label,x=float(v),value=float(y[i]),
       minimum=float(values['min'][i]),maximum=float(values['max'][i]),unit='percent',summary='mean of 30 deletion seeds'))
  ax.set_xlim(-.015,1.015);ax.set_ylim(-top*.025,top+top*.01);ax.set_xticks([0,.2,.4,.6,.8,1]);ax.set_yticks(ticks)
  ax.set_xlabel(f'({letter}) Field deletion probability');ax.set_ylabel(ylabel,labelpad=3);grid(ax)
  h,l=ax.get_legend_handles_labels();legend(ax,h,l,y=-.28,fontsize=8.5)
 save(fig,'Fig3_missing_evidence')
 CHECKS['missing_evidence']={'n_workflows':39,'n_attacks':9,'n_seeds':30,'all_three_panels_are_lines':True,
   'identical_comparators_explicitly_grouped':True,'values_unchanged':True,'markers_staggered_only_across_existing_x_values':True}
 rows=[]
 for metric in ['wrong','withheld','detected']:
  for key in ['pltl','ltl3','fo','tdid']:
   v=d['attacks'][key]['detected'] if metric=='detected' else d[metric][key]
   rows.extend(dict(metric=metric,judge=key,p=float(p),mean=v['mean'][i],minimum=v['min'][i],maximum=v['max'][i],
     denominator=9 if metric=='detected' else 39) for i,p in enumerate(x))
 outcsv(DATA/'Missing_evidence_values.csv',rows)


def runtime():
 raw=readcsv(DATA/'latency_summary.csv');old=readcsv(DATA/'original_memory.csv')
 assert len(raw)==105 and all(int(r['target_wrong'])==0 and int(r['completed'])==int(r['offered_runs']) for r in raw)
 assert all(r['preencode'].lower()=='true' for r in raw)
 loads=list(range(500,2001,250))
 fig,axs=plt.subplots(1,2,figsize=(7.16,2.80))
 fig.subplots_adjust(left=.075,right=.985,bottom=.29,top=.965,wspace=.30)
 handles=[];memout=[]
 for key,label,color,marker in STYLES:
  values=[]
  for load in loads:
   vs=[float(r['p95_ms']) for r in raw if r['judge']==key and int(r['load'])==load];assert len(vs)==3
   m=float(np.median(vs));values.append(m)
   plotted.append(dict(figure='Fig4',panel='latency',series=label,x=load,value=m,minimum=min(vs),maximum=max(vs),unit='ms',summary='median of 3 run-level p95 values'))
  ls={'pltl':'--','ltl3':':','fo':'-.','tdid_all':'-'}[key]
  h,=axs[0].plot(loads,values,color=color,marker=marker,ls=ls,lw=1.25,ms=4,mfc='white',mew=.95,label='T-DID' if key=='tdid_all' else label)
  handles.append(h)
 axs[0].set_xlim(450,2050);axs[0].set_xticks(loads);axs[0].set_ylim(0,6);axs[0].set_yticks([0,1,2,3,4,5,6])
 axs[0].set_xlabel('(a) Offered load (runs/s)');axs[0].set_ylabel('Scheduled-to-verdict p95 (ms)');grid(axs[0])
 for j,(key,label,color,marker) in enumerate(STYLES):
  oldkey='tdid' if key=='tdid_all' else key
  vs=np.array([float(r['peak_rss_kib'])/1024 for r in old if r['judge']==oldkey and int(r['n_proofs'])==10000]);assert len(vs)==3
  m=float(np.median(vs));axs[1].bar(j,m,color=color,width=.57,edgecolor='white',linewidth=.6)
  memout.append(dict(judge=oldkey,proofs=10000,median_peak_rss_mib=m,minimum=float(min(vs)),maximum=float(max(vs)),rules=1 if oldkey=='tdid' else 'configured'))
  plotted.append(dict(figure='Fig4',panel='matched_peak_RSS',series=oldkey,x=10000,value=m,minimum=float(min(vs)),maximum=float(max(vs)),unit='MiB',summary='median of 3 peak RSS values'))
 axs[1].set_xticks(range(4),['PLTL','LTL3','MonPoly','T-DID'])
 axs[1].set_ylim(0,60);axs[1].set_yticks([0,20,40,60]);axs[1].set_ylabel('Process peak RSS (MiB)')
 axs[1].set_xlabel('(b) Matched 10,000-proof workload');grid(axs[1])
 fig.legend(handles,[h.get_label() for h in handles],loc='lower center',ncol=4,frameon=False,
    bbox_to_anchor=(.5,.015),fontsize=9,handlelength=2.2,columnspacing=2.0)
 save(fig,'Fig4_runtime_cost')
 outcsv(DATA/'Matched_peak_RSS_values.csv',memout)
 CHECKS['runtime']={'main_panels':2,'latency_summary':'median of 3 repetitions at each of 7 loads',
    'all_four_configured_paths_preserved':True,'T_DID_latency_rules':21,'T_DID_peak_RSS_rules':1,
    'all_observed_ranges_preserved_in_supplement':True,'product_logging_cost_in_Table_VI':True,
    'state_growth_diagnosis_in_supplement_only':True,'values_unchanged':True}


def supplementary():
 # Full p95 distributions retained without overlaid trajectories.
 raw=readcsv(DATA/'latency_summary.csv');loads=list(range(500,2001,250))
 fig,axs=plt.subplots(2,2,figsize=(7.16,4.65),sharex=True,sharey=True)
 fig.subplots_adjust(left=.07,right=.98,bottom=.14,top=.98,wspace=.22,hspace=.39)
 for ax,(key,label,color,marker),letter in zip(axs.flat,STYLES,'abcd'):
  for load in loads:
   y=[float(r['p95_ms']) for r in raw if r['judge']==key and int(r['load'])==load]
   ax.scatter([load]*3,y,facecolors='white',edgecolors=color,marker=marker,s=20,lw=.85)
  mids=[np.median([float(r['p95_ms']) for r in raw if r['judge']==key and int(r['load'])==l]) for l in loads]
  ax.plot(loads,mids,color=color,lw=1.1,marker=marker,ms=3)
  ax.set_ylim(0,7);ax.set_xticks(loads);ax.set_xticklabels(loads,rotation=35,ha='right')
  ax.set_xlabel(f'({letter}) {label}: offered load (runs/s)');ax.set_ylabel('Run-level p95 (ms)');grid(ax)
 save(fig,'FigS1_latency_repeats')
 # Same scale, separate panels prevent 1/21 rule curves from concealing each other.
 rs=readcsv(DATA/'Memory_state_scaling.csv');fig,axs=plt.subplots(1,2,figsize=(7.16,2.6),sharey=True)
 fig.subplots_adjust(left=.07,right=.985,bottom=.25,top=.96,wspace=.16)
 for ax,rules,letter in zip(axs,[1,21],'ab'):
  v=[r for r in rs if int(r['rules'])==rules]
  ax.errorbar([int(r['n_proofs'])/1000 for r in v],[float(r['rss_mib']) for r in v],
   yerr=[[float(r['rss_mib'])-float(r['min_rss_mib']) for r in v],[float(r['max_rss_mib'])-float(r['rss_mib']) for r in v]],
   color=TEAL,fmt='o-',ms=3,mfc='white',lw=1.2,capsize=1.5)
  ax.set_ylim(0,150);ax.set_xlim(-2,102);ax.set_xticks(range(0,101,20));grid(ax)
  ax.set_xlabel(f'({letter}) {rules} active '+('rule' if rules==1 else 'rules')+': proofs (thousands)')
 axs[0].set_ylabel('Current process RSS (MiB)')
 save(fig,'FigS2_memory_rule_scope')

if __name__=='__main__':
 missing();runtime()

 for prefix,n in [("Fig3_missing_evidence",3),("Fig4_runtime_cost",4)]:
  for ext in ["pdf","svg","png"]:(OUT/f"{prefix}.{ext}").replace(OUT/f"Fig{n}.{ext}")
