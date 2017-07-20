# © 2016 and later: Unicode, Inc. and others.
# License & terms of use: http://www.unicode.org/copyright.html#License
GENRB_CLDR_VERSION = %version%
# A list of txt's to build
# The downstream packager may not need this file at all if their package is not
# constrained by
# the size (and/or their target OS already has ICU with the full locale data.)
#
# Listed below are locale data files necessary for 40 + 1 + 8 languages Chrome
# is localized to.
#
# In addition to them, 40+ "abridged" locale data files are listed. Chrome is
# localized to them, but
# uses a few categories of data in those locales for IDN handling and language
# name listing (in the UI).
# Aliases which do not have a corresponding xx.xml file (see icu-config.xml &
# build.xml)
GENRB_SYNTHETIC_ALIAS =

# All aliases (to not be included under 'installed'), but not including root.
GENRB_ALIAS_SOURCE = $(GENRB_SYNTHETIC_ALIAS)\
 zh_CN.txt zh_TW.txt zh_HK.txt zh_SG.txt\
 no.txt in.txt iw.txt tl.txt sh.txt

# Ordinary resources
GENRB_SOURCE =\
 am.txt\
 ar.txt\
 ar_DZ.txt ar_EH.txt ar_LB.txt ar_LY.txt ar_MA.txt ar_MR.txt ar_SA.txt\
 ar_SO.txt ar_TN.txt\
 bg.txt\
 bn.txt\
 ca.txt\
 cs.txt\
 da.txt\
 de.txt de_AT.txt de_CH.txt\
 el.txt\
 en.txt en_001.txt en_150.txt\
 en_GB.txt en_US.txt en_AU.txt en_CA.txt en_HK.txt en_IN.txt en_NZ.txt\
 en_SG.txt en_ZA.txt\
 es.txt es_ES.txt es_419.txt es_AR.txt es_MX.txt es_US.txt\
 es_BO.txt es_BR.txt es_BZ.txt es_CL.txt es_CO.txt es_CR.txt es_CU.txt\
 es_DO.txt es_EA.txt es_EC.txt es_GQ.txt es_GT.txt es_HN.txt es_IC.txt\
 es_NI.txt es_PA.txt es_PE.txt es_PH.txt es_PR.txt es_PY.txt es_SV.txt\
 es_UY.txt es_VE.txt\
 et.txt\
 fa.txt\
 fi.txt\
 fil.txt\
 fr.txt fr_CA.txt fr_CH.txt\
 gu.txt\
 he.txt\
 hi.txt\
 hr.txt\
 hu.txt\
 id.txt\
 it.txt it_CH.txt\
 ja.txt\
 kn.txt\
 ko.txt\
 lt.txt\
 lv.txt\
 ml.txt\
 mr.txt\
 ms.txt\
 nb.txt\
 nl.txt\
 pl.txt\
 pt.txt pt_BR.txt pt_PT.txt\
 ro.txt\
 ru.txt\
 sk.txt\
 sl.txt\
 sr.txt\
 sv.txt\
 sw.txt\
 ta.txt\
 te.txt\
 th.txt\
 tr.txt\
 uk.txt\
 vi.txt\
 zh.txt zh_Hans.txt zh_Hans_CN.txt zh_Hans_SG.txt\
 zh_Hant.txt zh_Hant_TW.txt zh_Hant_HK.txt\
 af.txt\
 ak.txt\
 an.txt\
 ast.txt\
 az.txt\
 be.txt\
 bem.txt\
 br.txt\
 bs.txt\
 ckb.txt\
 cy.txt\
 ee.txt\
 eo.txt\
 eu.txt\
 fo.txt\
 ga.txt\
 gl.txt\
 ha.txt\
 haw.txt\
 hy.txt\
 ig.txt\
 is.txt\
 ka.txt\
 kk.txt\
 km.txt\
 ku.txt\
 ky.txt\
 lg.txt\
 ln.txt\
 lo.txt\
 mfe.txt\
 mg.txt\
 mk.txt\
 mn.txt\
 mo.txt ro_MD.txt\
 mt.txt\
 my.txt\
 ne.txt\
 nn.txt\
 nyn.txt\
 om.txt\
 or.txt\
 pa.txt\
 ps.txt\
 rm.txt\
 rn.txt\
 rw.txt\
 si.txt\
 sn.txt\
 so.txt\
 sq.txt\
 sr_Latn.txt\
 tg.txt\
 ti.txt\
 to.txt\
 ur.txt\
 uz.txt\
 wa.txt\
 yo.txt\
 zu.txt
