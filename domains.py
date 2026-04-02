"""Domain and Entity definitions for OSDU"""

DOMAINS = {
    "General Data": {
        "description": "Master data được nạp bởi general_data_ingestion_pipeline",
        "icon": "🏔️",
        "entities": {
            "Agreement": {
                "kind": "osdu:wks:master-data--Agreement:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Agreement:*"],
                "description": "Thỏa thuận / hợp đồng",
                "fields": ["AgreementName", "AgreementType", "EffectiveDate"]
            },
            "Basin": {
                "kind": "osdu:wks:master-data--Basin:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Basin:*"],
                "description": "Lưu vực trầm tích",
                "fields": ["BasinName", "Country", "Province"]
            },
            "Field": {
                "kind": "osdu:wks:master-data--Field:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Field:*"],
                "description": "Mỏ dầu khí",
                "fields": ["FieldName", "Country", "DiscoveryDate"]
            },
            "GeopoliticalEntity": {
                "kind": "osdu:wks:master-data--GeopoliticalEntity:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--GeopoliticalEntity:*"],
                "description": "Đơn vị địa chính trị",
                "fields": ["GeoPoliticalEntityName", "Name", "GeopoliticalEntityType"]
            },
            "Organisation": {
                "kind": "osdu:wks:master-data--Organisation:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Organisation:*"],
                "description": "Tổ chức, công ty",
                "fields": ["OrganisationName", "OrganisationType"]
            },
            "Reservoir": {
                "kind": "osdu:wks:master-data--Reservoir:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Reservoir:*"],
                "description": "Tầng chứa",
                "fields": ["ReservoirName", "FieldID", "Formation"]
            },
            "Rig": {
                "kind": "osdu:wks:master-data--Rig:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Rig:*"],
                "description": "Giàn khoan",
                "fields": ["RigName", "RigType", "Owner"]
            },
            "Well": {
                "kind": "osdu:wks:master-data--Well:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Well:*"],
                "description": "Giếng khoan",
                "fields": ["WellName", "WellType", "SpudDate"]
            }
        }
    },
    "Wellbore Domain": {
        "description": "Entity được nạp bởi wellbore_data_ingestion_pipeline",
        "icon": "🕳️",
        "entities": {
            "Wellbore": {
                "kind": "osdu:wks:master-data--Wellbore:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Wellbore:*"],
                "description": "Thân giếng",
                "fields": ["WellboreName", "WellID", "FinalTotalDepth"]
            },
            "WellLogAcquisition": {
                "kind": "osdu:wks:master-data--WellLogAcquisition:*",
                "description": "Phiên thu thập well log",
                "fields": ["ProjectName", "BeginDate", "EndDate"]
            },
            "WellLog": {
                "kind": "osdu:wks:work-product-component--WellLog:*",
                "description": "Log giếng khoan",
                "fields": ["LogName", "WellboreID", "LogType"]
            },
            "WellboreIntervalSet": {
                "kind": "osdu:wks:work-product-component--WellboreIntervalSet:*",
                "description": "Bộ khoảng giếng khoan",
                "fields": ["WellboreID", "IntervalName", "StartMeasuredDepth"]
            },
            "WellboreMarkerSet": {
                "kind": "osdu:wks:work-product-component--WellboreMarkerSet:*",
                "description": "Bộ marker giếng khoan",
                "fields": ["WellboreID", "MarkerName", "MeasuredDepth"]
            },
            "WellboreTrajectory": {
                "kind": "osdu:wks:work-product-component--WellboreTrajectory:*",
                "description": "Quỹ đạo giếng khoan",
                "fields": ["WellboreID", "TrajectoryType", "SurveyVersion"]
            }
        }
    },
    "Seismic Domain": {
        "description": "Entity được nạp bởi seismic_data_ingestion_pipeline",
        "icon": "📊",
        "entities": {
            "SeismicAcquisitionDocuments": {
                "kind": "osdu:wks:dataset--Document:*",
                "description": "Tài liệu acquisition địa chấn",
                "fields": ["DocumentName", "SurveyName", "DocumentType"]
            },
            "SeismicBinGrid": {
                "kind": "osdu:wks:master-data--BinGrid:*",
                "description": "Lưới bin địa chấn",
                "fields": ["BinGridName", "SurveyName", "BinSize"]
            },
            "SeismicFieldTraceData": {
                "kind": "osdu:wks:work-product-component--SeismicFieldTraceData:*",
                "description": "Trace data từ field",
                "fields": ["SurveyName", "LineName", "TraceCount"]
            },
            "SeismicLineGeometry": {
                "kind": "osdu:wks:master-data--SeismicLineGeometry:*",
                "description": "Hình học tuyến địa chấn",
                "fields": ["LineName", "SurveyName", "Length"]
            },
            "SeismicTraceData": {
                "kind": "osdu:wks:work-product-component--SeismicTraceData:*",
                "description": "Trace data địa chấn",
                "fields": ["SeismicLineName", "Domain", "SampleInterval"]
            },
            "SeismicFault": {
                "kind": "osdu:wks:work-product-component--SeismicFault:*",
                "description": "Fault địa chấn",
                "fields": ["FaultName", "SurveyName", "InterpretationDate"]
            },
            "SeismicHorizon": {
                "kind": "osdu:wks:work-product-component--SeismicHorizon:*",
                "description": "Horizon địa chấn",
                "fields": ["HorizonName", "SurveyName", "InterpretationDate"]
            },
            "VelocityModeling": {
                "kind": "osdu:wks:master-data--SeismicProcessingProject:*",
                "description": "Mô hình velocity / processing project",
                "fields": ["ProcessingProjectName", "StartDate", "EndDate"]
            }
        }
    }
}


def get_domain_list():
    """Get list of all domains"""
    return list(DOMAINS.keys())


def get_domain_info(domain_name):
    """Get information about a specific domain"""
    return DOMAINS.get(domain_name)


def get_entity_info(domain_name, entity_name):
    """Get information about a specific entity"""
    domain = DOMAINS.get(domain_name)
    if domain:
        return domain.get('entities', {}).get(entity_name)
    return None


def get_all_entities():
    """Get all entities across all domains"""
    all_entities = {}
    for domain_name, domain_info in DOMAINS.items():
        for entity_name, entity_info in domain_info['entities'].items():
            all_entities[f"{domain_name}.{entity_name}"] = {
                "domain": domain_name,
                "entity": entity_name,
                **entity_info
            }
    return all_entities


def search_entities(search_term):
    """Search for entities by name or description"""
    results = []
    search_lower = search_term.lower()
    
    for domain_name, domain_info in DOMAINS.items():
        for entity_name, entity_info in domain_info['entities'].items():
            if (search_lower in entity_name.lower() or 
                search_lower in entity_info['description'].lower()):
                results.append({
                    "domain": domain_name,
                    "entity": entity_name,
                    "kind": entity_info['kind'],
                    "description": entity_info['description']
                })
    
    return results