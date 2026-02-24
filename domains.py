"""Domain and Entity definitions for OSDU"""

DOMAINS = {
    "General Data": {
        "description": "Dữ liệu địa chất và địa lý cơ bản",
        "icon": "🏔️",
        "entities": {
            "Basin": {
                "kind": "osdu:wks:master-data--Basin:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Basin:*"],
                "description": "Lưu vực trầm tích",
                "fields": ["BasinName", "Country", "Province"]
            },
            "Block": {
                "kind": "osdu:wks:master-data--Block:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Block:*"],
                "description": "Khối thăm dò",
                "fields": ["BlockName", "Country", "Operator"]
            },
            "Field": {
                "kind": "osdu:wks:master-data--Field:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Field:*"],
                "description": "Mỏ dầu khí",
                "fields": ["FieldName", "Country", "DiscoveryDate"]
            },
            "Reservoir": {
                "kind": "osdu:wks:master-data--Reservoir:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Reservoir:*"],
                "description": "Tầng chứa",
                "fields": ["ReservoirName", "FieldID", "Formation"]
            },
            "Well": {
                "kind": "osdu:wks:master-data--Well:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Well:*"],
                "description": "Giếng khoan",
                "fields": ["WellName", "WellType", "SpudDate"]
            },
            "Wellbore": {
                "kind": "osdu:wks:master-data--Wellbore:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Wellbore:*"],
                "description": "Thân giếng",
                "fields": ["WellboreName", "WellID", "FinalTotalDepth"]
            },
            "GeopoliticalEntity": {
                "kind": "osdu:wks:master-data--GeopoliticalEntity:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--GeopoliticalEntity:*"],
                "description": "Đơn vị địa chính trị",
                "fields": ["Name", "GeopoliticalEntityType"]
            },
            "Organisation": {
                "kind": "osdu:wks:master-data--Organisation:*",
                "kind_alternatives": ["osdu:ddms-wellbore:master-data--Organisation:*"],
                "description": "Tổ chức, công ty",
                "fields": ["OrganisationName", "OrganisationType"]
            }
        }
    },
    "Wellbore Domain": {
        "description": "Dữ liệu liên quan đến giếng khoan",
        "icon": "🕳️",
        "entities": {
            "WellLog": {
                "kind": "osdu:wks:well-log--WellLog:*",
                "description": "Log giếng khoan",
                "fields": ["LogName", "WellboreID", "LogType"]
            },
            "WellboreTrajectory": {
                "kind": "osdu:wks:wellbore--WellboreTrajectory:*",
                "description": "Quỹ đạo giếng khoan",
                "fields": ["WellboreID", "TrajectoryType"]
            },
            "WellboreMarkerSet": {
                "kind": "osdu:wks:wellbore--WellboreMarkerSet:*",
                "description": "Bộ marker giếng khoan",
                "fields": ["WellboreID", "MarkerSetName"]
            },
            "WellboreCompletion": {
                "kind": "osdu:wks:wellbore--WellboreCompletion:*",
                "description": "Hoàn thiện giếng",
                "fields": ["WellboreID", "CompletionType"]
            },
            "WellLogChannel": {
                "kind": "osdu:wks:well-log--WellLogChannel:*",
                "description": "Kênh đo log",
                "fields": ["ChannelName", "WellLogID", "Unit"]
            },
            "LoggingTool": {
                "kind": "osdu:wks:well-log--LoggingTool:*",
                "description": "Thiết bị đo log",
                "fields": ["ToolName", "ToolType", "Vendor"]
            },
            "CoredInterval": {
                "kind": "osdu:wks:wellbore--CoredInterval:*",
                "description": "Khoảng lấy mẫu lõi",
                "fields": ["WellboreID", "TopDepth", "BottomDepth"]
            }
        }
    },
    "Work/Project Domain": {
        "description": "Dữ liệu dự án và sản phẩm làm việc",
        "icon": "📁",
        "entities": {
            "Project": {
                "kind": "osdu:wks:project--Project:*",
                "description": "Dự án",
                "fields": ["ProjectName", "ProjectType", "StartDate"]
            },
            "WorkProduct": {
                "kind": "osdu:wks:work-product--WorkProduct:*",
                "description": "Sản phẩm làm việc",
                "fields": ["WorkProductName", "ProjectID", "WorkProductType"]
            },
            "WorkProductComponent": {
                "kind": "osdu:wks:work-product-component--WorkProductComponent:*",
                "description": "Thành phần sản phẩm",
                "fields": ["ComponentName", "WorkProductID"]
            },
            "Activity": {
                "kind": "osdu:wks:activity--Activity:*",
                "description": "Hoạt động",
                "fields": ["ActivityName", "ActivityType", "StartDate"]
            },
            "ActivityTemplate": {
                "kind": "osdu:wks:activity--ActivityTemplate:*",
                "description": "Mẫu hoạt động",
                "fields": ["TemplateName", "ActivityType"]
            }
        }
    },
    "Seismic Domain": {
        "description": "Dữ liệu địa chấn",
        "icon": "📊",
        "entities": {
            "SeismicSurvey": {
                "kind": "osdu:wks:seismic--SeismicSurvey:*",
                "description": "Khảo sát địa chấn",
                "fields": ["SurveyName", "SurveyType", "AcquisitionDate"]
            },
            "Seismic2D": {
                "kind": "osdu:wks:seismic--Seismic2D:*",
                "description": "Địa chấn 2D",
                "fields": ["SurveyName", "LineCount"]
            },
            "Seismic3D": {
                "kind": "osdu:wks:seismic--Seismic3D:*",
                "description": "Địa chấn 3D",
                "fields": ["SurveyName", "BinSize", "Coverage"]
            },
            "SeismicLine": {
                "kind": "osdu:wks:seismic--SeismicLine:*",
                "description": "Tuyến địa chấn",
                "fields": ["LineName", "SurveyID", "Length"]
            },
            "SeismicAcquisitionSurvey": {
                "kind": "osdu:wks:seismic--SeismicAcquisitionSurvey:*",
                "description": "Thu thập dữ liệu địa chấn",
                "fields": ["SurveyName", "Contractor", "Equipment"]
            }
        }
    },
    "Files Domain": {
        "description": "Dữ liệu file và dataset",
        "icon": "📄",
        "entities": {
            "File": {
                "kind": "osdu:wks:dataset--File:*",
                "description": "File dữ liệu",
                "fields": ["FileName", "FileSize", "FileType"]
            },
            "Dataset": {
                "kind": "osdu:wks:dataset--Dataset:*",
                "description": "Bộ dữ liệu",
                "fields": ["DatasetName", "DatasetType", "CreationDate"]
            },
            "FileCollection": {
                "kind": "osdu:wks:dataset--FileCollection:*",
                "description": "Bộ sưu tập file",
                "fields": ["CollectionName", "FileCount"]
            }
        }
    },
    "Reference Domain": {
        "description": "Dữ liệu tham chiếu và chuẩn",
        "icon": "📚",
        "entities": {
            "ReferenceData": {
                "kind": "osdu:wks:reference-data--ReferenceData:*",
                "description": "Dữ liệu tham chiếu",
                "fields": ["Name", "Type", "Version"]
            },
            "Unit": {
                "kind": "osdu:wks:unit--Unit:*",
                "description": "Đơn vị đo lường",
                "fields": ["UnitName", "UnitType", "Symbol"]
            },
            "CRS": {
                "kind": "osdu:wks:crs--CRS:*",
                "description": "Hệ tọa độ tham chiếu",
                "fields": ["CRSName", "CRSType", "Authority"]
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